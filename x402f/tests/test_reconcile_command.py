from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from x402f.management.commands.reconcile_x402 import reconcile_record
from x402f.models import X402Authorization


def record(*, transaction_hash=None, prepared_transaction=None):  # noqa: ANN001
    return X402Authorization.objects.create(
        nonce=f"nonce-{X402Authorization.objects.count()}",
        payer="payer",
        pay_to="payee",
        value="100",
        valid_after=timezone.now(),
        valid_before=timezone.now() + timedelta(minutes=10),
        signature="signature",
        payment_requirements={"network": "eip155:8453"},
        payment_payload={},
        status=X402Authorization.Status.SETTLING,
        transaction_hash=transaction_hash,
        prepared_transaction=prepared_transaction,
        settling_started_at=timezone.now() - timedelta(minutes=10),
    )


class ReconciliationCommandTests(TestCase):
    @patch("x402f.management.commands.reconcile_x402._configured")
    @patch("x402f.management.commands.reconcile_x402._transaction_status")
    def test_confirmed_and_failed_transactions_are_reconciled(self, status, configured) -> None:
        signer = Mock()
        configured.return_value = SimpleNamespace(signer_for=lambda _network: signer)
        confirmed = record(transaction_hash="0xconfirmed")
        failed = record(transaction_hash="0xfailed", prepared_transaction="raw")
        status.side_effect = ["confirmed", "failed"]

        self.assertEqual(reconcile_record(confirmed), "settled")
        self.assertEqual(reconcile_record(failed), "failed_released")
        confirmed.refresh_from_db()
        failed.refresh_from_db()
        self.assertEqual(confirmed.status, X402Authorization.Status.SETTLED)
        self.assertEqual(failed.status, X402Authorization.Status.VERIFIED)
        self.assertIsNone(failed.transaction_hash)

    @patch("x402f.management.commands.reconcile_x402._signer_lock")
    @patch("x402f.management.commands.reconcile_x402._broadcast_prepared")
    @patch("x402f.management.commands.reconcile_x402._configured")
    @patch("x402f.management.commands.reconcile_x402._transaction_status", return_value="pending")
    def test_pending_prepared_transaction_replays_identically(self, _status, configured, broadcast, lock) -> None:
        signer = Mock()
        configured.return_value = SimpleNamespace(signer_for=lambda _network: signer)
        lock.return_value = __import__("contextlib").nullcontext()
        pending = record(transaction_hash="0xpending", prepared_transaction="raw")
        broadcast.return_value = "0xpending"

        self.assertEqual(reconcile_record(pending), "rebroadcast")
        broadcast.assert_called_once_with(signer, "raw", "eip155:8453")

    def test_stale_unsubmitted_claim_is_released(self) -> None:
        stale = record()
        self.assertEqual(reconcile_record(stale), "released")
        stale.refresh_from_db()
        self.assertEqual(stale.status, X402Authorization.Status.VERIFIED)

    @override_settings(X402_PREPARED_MAX_AGE_SECONDS=60)
    @patch("x402f.management.commands.reconcile_x402._configured")
    @patch("x402f.management.commands.reconcile_x402._transaction_status", return_value="pending")
    def test_old_pending_svm_prepared_transaction_expires(self, _status, configured) -> None:
        configured.return_value = SimpleNamespace(signer_for=lambda _network: Mock())
        pending = record(transaction_hash="0xpending", prepared_transaction="raw")
        pending.payment_requirements = {"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"}
        pending.save(update_fields=["payment_requirements"])

        self.assertEqual(reconcile_record(pending), "expired")
        pending.refresh_from_db()
        self.assertEqual(pending.status, X402Authorization.Status.FAILED)

    @override_settings(X402_PREPARED_MAX_AGE_SECONDS=60)
    @patch("x402f.management.commands.reconcile_x402._signer_lock")
    @patch("x402f.management.commands.reconcile_x402._broadcast_prepared", return_value="0xpending")
    @patch("x402f.management.commands.reconcile_x402._configured")
    @patch("x402f.management.commands.reconcile_x402._transaction_status", return_value="pending")
    def test_old_pending_evm_transaction_keeps_nonce_reserved(self, _status, configured, _broadcast, lock) -> None:
        configured.return_value = SimpleNamespace(signer_for=lambda _network: Mock())
        lock.return_value = __import__("contextlib").nullcontext()
        pending = record(transaction_hash="0xpending", prepared_transaction="raw")

        self.assertEqual(reconcile_record(pending), "rebroadcast")
        pending.refresh_from_db()
        self.assertEqual(pending.status, X402Authorization.Status.SETTLING)

    @override_settings(X402_SETTLEMENT_LEASE_SECONDS=1)
    def test_command_processes_only_stale_records(self) -> None:
        stale = record()
        fresh = record()
        X402Authorization.objects.filter(pk=fresh.pk).update(settling_started_at=timezone.now())
        output = StringIO()

        call_command("reconcile_x402", stdout=output)

        stale.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual(stale.status, X402Authorization.Status.VERIFIED)
        self.assertEqual(fresh.status, X402Authorization.Status.SETTLING)
        self.assertIn("processed", output.getvalue())
