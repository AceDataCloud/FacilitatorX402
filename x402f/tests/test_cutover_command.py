from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from x402f.models import X402Authorization


def _authorization(*, network: str, status: str, expired: bool, transaction_hash=None, prepared_transaction=None):
    now = timezone.now()
    return X402Authorization.objects.create(
        nonce=f"{network}-{status}-{X402Authorization.objects.count()}",
        payer="payer",
        pay_to="payee",
        value="1",
        valid_after=now - timedelta(minutes=2),
        valid_before=now + (-timedelta(minutes=1) if expired else timedelta(minutes=1)),
        signature="signature",
        payment_requirements={"network": network},
        payment_payload={},
        status=status,
        transaction_hash=transaction_hash,
        prepared_transaction=prepared_transaction,
    )


@pytest.mark.django_db
def test_preflight_fails_only_safe_expired_legacy_authorizations() -> None:
    safe = _authorization(network="base", status=X402Authorization.Status.VERIFIED, expired=True)
    canonical = _authorization(network="eip155:8453", status=X402Authorization.Status.VERIFIED, expired=True)

    output = StringIO()
    call_command("check_official_v2_cutover", "--fail-expired", stdout=output)

    safe.refresh_from_db()
    canonical.refresh_from_db()
    assert safe.status == X402Authorization.Status.FAILED
    assert canonical.status == X402Authorization.Status.VERIFIED
    assert "Marked 1 expired legacy authorizations as failed" in output.getvalue()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "status,expired,transaction_hash,prepared_transaction",
    [
        (X402Authorization.Status.VERIFIED, False, None, None),
        (X402Authorization.Status.SETTLING, True, None, None),
        (X402Authorization.Status.VERIFIED, True, "0xtx", None),
        (X402Authorization.Status.VERIFIED, True, None, "raw-transaction"),
    ],
)
def test_preflight_keeps_unsafe_legacy_authorizations_blocking(
    status: str,
    expired: bool,
    transaction_hash: str | None,
    prepared_transaction: str | None,
) -> None:
    record = _authorization(
        network="solana",
        status=status,
        expired=expired,
        transaction_hash=transaction_hash,
        prepared_transaction=prepared_transaction,
    )

    with pytest.raises(CommandError, match="1 nonterminal legacy"):
        call_command("check_official_v2_cutover", "--fail-expired")

    record.refresh_from_db()
    assert record.status == status
