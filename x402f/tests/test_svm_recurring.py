import struct
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from x402f.models import X402Authorization
from x402f.svm_recurring import (
    PERIOD_SECONDS,
    PROFILE,
    RecurringDelegation,
    available_amount,
    parse_recurring_delegation,
    recurring_nonce,
)
from x402f.views_official import PaymentIdentity, _settle_recurring

PROGRAM = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PAY_TO = "11111111111111111111111111111112"
WALLET = "11111111111111111111111111111113"
PAYER = "11111111111111111111111111111114"
AUTHORITY = "11111111111111111111111111111115"
DELEGATION = "11111111111111111111111111111116"
NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


def _delegation(delegatee: str, *, pulled: int = 100, current_period_start_ts: int | None = None):
    now = int(timezone.now().timestamp())
    return RecurringDelegation(
        address=DELEGATION,
        wallet=WALLET,
        delegatee=delegatee,
        payer=PAYER,
        authority_init_id=42,
        subscription_authority=AUTHORITY,
        mint=MINT,
        current_period_start_ts=current_period_start_ts or now,
        period_seconds=PERIOD_SECONDS,
        expiry_ts=now + PERIOD_SECONDS,
        amount_per_period=1000,
        amount_pulled_in_period=pulled,
    )


def _account_bytes(delegatee: str) -> bytes:
    delegation = _delegation(delegatee)
    return b"".join(
        [
            bytes([3, 1, 255]),
            bytes(Pubkey.from_string(WALLET)),
            bytes(Pubkey.from_string(delegatee)),
            bytes(Pubkey.from_string(PAYER)),
            struct.pack("<q", 42),
            bytes(Pubkey.from_string(AUTHORITY)),
            bytes(Pubkey.from_string(MINT)),
            struct.pack("<q", delegation.current_period_start_ts),
            struct.pack("<Q", PERIOD_SECONDS),
            struct.pack("<q", delegation.expiry_ts),
            struct.pack("<Q", 1000),
            struct.pack("<Q", 100),
        ]
    )


class SvmRecurringTests(TestCase):
    def setUp(self):
        self.keypair = Keypair()
        self.private_key = str(self.keypair)
        self.delegatee = str(self.keypair.pubkey())
        self.settings = override_settings(
            X402_SOLANA_SIGNER_PRIVATE_KEY=self.private_key,
            X402_SOLANA_SUBSCRIPTIONS_PROGRAM=PROGRAM,
            X402_SOLANA_ASSET=MINT,
            X402_SOLANA_PAY_TO=PAY_TO,
        )
        self.settings.enable()
        self.addCleanup(self.settings.disable)

    def test_parse_v04_layout(self):
        parsed = parse_recurring_delegation(DELEGATION, _account_bytes(self.delegatee))
        self.assertEqual(parsed.wallet, WALLET)
        self.assertEqual(parsed.delegatee, self.delegatee)
        self.assertEqual(parsed.authority_init_id, 42)
        self.assertEqual(parsed.amount_per_period, 1000)
        self.assertEqual(parsed.amount_pulled_in_period, 100)

    def test_nonce_binds_profile_network_delegation_and_request(self):
        first = recurring_nonce(NETWORK, DELEGATION, "request-1")
        self.assertNotEqual(first, recurring_nonce(NETWORK, DELEGATION, "request-2"))
        self.assertNotEqual(first, recurring_nonce(NETWORK, WALLET, "request-1"))

    def test_available_amount_subtracts_active_reservations(self):
        now = timezone.now()
        X402Authorization.objects.create(
            nonce="reserved",
            payer=WALLET,
            pay_to=PAY_TO,
            value="250",
            valid_after=now,
            valid_before=now + timedelta(minutes=2),
            signature="digest",
            payment_requirements={"network": NETWORK, "amount": "250"},
            payment_payload={"payload": {"authorizationProfile": PROFILE, "delegation": DELEGATION}},
            scheme="upto",
        )
        self.assertEqual(available_amount(_delegation(self.delegatee)), 650)

    def test_available_amount_resets_stale_on_chain_period(self):
        stale = int(timezone.now().timestamp()) - PERIOD_SECONDS - 1
        self.assertEqual(available_amount(_delegation(self.delegatee, pulled=900, current_period_start_ts=stale)), 1000)

    def test_zero_amount_releases_without_transfer(self):
        record = self._record()
        response = _settle_recurring(record, self._identity(), "0", NETWORK)
        record.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        self.assertEqual(record.status, X402Authorization.Status.RELEASED)
        self.assertEqual(record.settled_amount, "0")

    @patch("x402f.views_official.send_recurring_prepared", return_value="tx-signature")
    @patch("x402f.views_official.build_transfer_transaction", return_value=("tx-signature", "prepared"))
    @patch("x402f.views_official.verify_recurring")
    def test_settle_persists_prepared_before_broadcast(self, verify, build, send):
        verify.return_value = (_delegation(self.delegatee), 900)
        record = self._record()
        observed = []

        def assert_prepared(value):
            current = X402Authorization.objects.get(pk=record.pk)
            observed.append((current.transaction_hash, current.prepared_transaction))
            return "tx-signature"

        send.side_effect = assert_prepared
        response = _settle_recurring(record, self._identity(), "200", NETWORK)
        record.refresh_from_db()
        self.assertTrue(response.data["success"])
        self.assertEqual(observed, [("tx-signature", "prepared")])
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(record.settled_amount, "200")
        build.assert_called_once()

    def _record(self):
        now = timezone.now()
        return X402Authorization.objects.create(
            nonce="request-nonce",
            payer=WALLET,
            pay_to=PAY_TO,
            value="500",
            valid_after=now,
            valid_before=now + timedelta(minutes=2),
            signature="digest",
            payment_requirements={"network": NETWORK, "amount": "500"},
            payment_payload={
                "payload": {
                    "authorizationProfile": PROFILE,
                    "delegation": DELEGATION,
                    "requestNonce": "request-1",
                }
            },
            scheme="upto",
        )

    @staticmethod
    def _identity():
        now = timezone.now()
        return PaymentIdentity(
            nonce="request-nonce",
            payer=WALLET,
            signature="digest",
            valid_after=now,
            valid_before=now + timedelta(minutes=2),
        )
