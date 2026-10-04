from datetime import timedelta
from time import monotonic

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.utils import timezone
from x402.mechanisms.svm.constants import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2

from x402f import envar_policy
from x402f.models import X402Authorization
from x402f.official import SKALE_MAINNET
from x402f.svm_recurring import is_recurring_payload
from x402f.views_official import (
    _broadcast_prepared,
    _configured,
    _signer_lock,
    _transaction_status,
    advance_recurring_settlement,
)

LEGACY_NETWORKS = {
    "base": "eip155:8453",
    "skale": SKALE_MAINNET,
    "solana": SOLANA_MAINNET_CAIP2,
    "solana-devnet": SOLANA_DEVNET_CAIP2,
}


def reconcile_record(record: X402Authorization) -> str:
    if str(record.verification_id or "").startswith("envar:legacy:"):
        return "legacy_review"
    stored_network = str(record.payment_requirements.get("network") or "")
    if not stored_network:
        return "invalid"
    network = LEGACY_NETWORKS.get(stored_network, stored_network)
    if is_recurring_payload(record.payment_payload):
        renewed_at = timezone.now()
        renewed = X402Authorization.objects.filter(
            pk=record.pk,
            status=X402Authorization.Status.SETTLING,
            settling_started_at=record.settling_started_at,
        ).update(settling_started_at=renewed_at)
        if renewed != 1:
            return "conflict"
        record.settling_started_at = renewed_at
        return advance_recurring_settlement(record, network)
    if not record.transaction_hash:
        updated = X402Authorization.objects.filter(
            pk=record.pk,
            status=X402Authorization.Status.SETTLING,
            transaction_hash__isnull=True,
            settling_started_at=record.settling_started_at,
        ).update(status=X402Authorization.Status.VERIFIED, settling_started_at=None, settled_amount=None)
        return "released" if updated == 1 else "conflict"

    configured = _configured(network)
    signer = configured.signer_for(network)
    transaction_status = _transaction_status(signer, record.transaction_hash, network)
    if transaction_status == "confirmed":
        if envar_policy.is_envar(record) and not envar_policy.transfer_proven(record, signer):
            return "pending_proof"
        updated = X402Authorization.objects.filter(
            pk=record.pk,
            status=X402Authorization.Status.SETTLING,
            transaction_hash=record.transaction_hash,
        ).update(status=X402Authorization.Status.SETTLED, settled_at=timezone.now(), settling_started_at=None)
        return "settled" if updated == 1 else "conflict"
    if transaction_status == "failed":
        if envar_policy.is_envar(record):
            updated = X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                transaction_hash=record.transaction_hash,
            ).update(status=X402Authorization.Status.FAILED, settling_started_at=None)
            return "failed" if updated == 1 else "conflict"
        updated = X402Authorization.objects.filter(
            pk=record.pk,
            status=X402Authorization.Status.SETTLING,
            transaction_hash=record.transaction_hash,
        ).update(
            status=X402Authorization.Status.VERIFIED,
            transaction_hash=None,
            prepared_transaction=None,
            signer_nonce=None,
            transaction_broadcast_at=None,
            settling_started_at=None,
            settled_amount=None,
        )
        return "failed_released" if updated == 1 else "conflict"
    if transaction_status == "pending" and record.prepared_transaction:
        max_age = timedelta(seconds=settings.X402_PREPARED_MAX_AGE_SECONDS)
        if (
            network.startswith("solana:")
            and record.settling_started_at
            and record.settling_started_at < timezone.now() - max_age
        ):
            updated = X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                transaction_hash=record.transaction_hash,
            ).update(status=X402Authorization.Status.FAILED, settling_started_at=None)
            return "expired" if updated == 1 else "conflict"
        with _signer_lock(network):
            submitted = _broadcast_prepared(signer, record.prepared_transaction, network)
        if submitted != record.transaction_hash:
            raise CommandError("prepared transaction replay returned a different transaction")
        X402Authorization.objects.filter(
            pk=record.pk,
            status=X402Authorization.Status.SETTLING,
            transaction_hash=record.transaction_hash,
        ).update(transaction_broadcast_at=timezone.now())
        return "rebroadcast"
    return "pending"


class Command(BaseCommand):
    help = "Reconcile stale official x402 settlements"

    def add_arguments(self, parser) -> None:  # noqa: ANN001
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--max-runtime-seconds", type=int, default=240)

    def handle(self, *args, **options):  # noqa: ANN002, ANN003, ANN201
        limit = options["limit"]
        if limit <= 0 or limit > 1000:
            raise CommandError("limit must be between 1 and 1000")
        max_runtime = options["max_runtime_seconds"]
        if max_runtime <= 0:
            raise CommandError("max-runtime-seconds must be positive")
        deadline = monotonic() + max_runtime
        cutoff = timezone.now() - timedelta(seconds=settings.X402_SETTLEMENT_LEASE_SECONDS)
        records = list(
            X402Authorization.objects.filter(
                Q(status=X402Authorization.Status.SETTLING),
                Q(settling_started_at__lt=cutoff),
            ).order_by("settling_started_at")[:limit]
        )
        outcomes: dict[str, int] = {}
        for record in records:
            if monotonic() + settings.X402_TX_TIMEOUT_SECONDS + 10 >= deadline:
                break
            try:
                outcome = reconcile_record(record)
            except Exception as exc:
                outcome = "error"
                self.stderr.write(f"{record.pk}: {type(exc).__name__}")
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        self.stdout.write(str({"processed": sum(outcomes.values()), "outcomes": outcomes}))
        if outcomes.get("error"):
            raise CommandError(f"reconciliation failed for {outcomes['error']} record(s)")
