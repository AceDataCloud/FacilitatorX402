import json
import os
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from web3 import Web3

from x402f.chain_handlers.base import SettlementResult, TransactionStatus
from x402f.models import X402Authorization
from x402f.views_multichain import _signer_lock


class X402MultichainViewTests(TestCase):
    """Tests for the production views_multichain views."""

    def setUp(self) -> None:
        self.signer_account = Account.create("x402-facilitator-signer")
        self.payer_account = Account.create("x402-facilitator-payer")

        pay_to = self.signer_account.address
        usdc_contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

        overrides = override_settings(
            X402_BASE_RPC_URL="http://localhost:8545",
            X402_BASE_SIGNER_PRIVATE_KEY=self.signer_account.key.hex(),
            X402_BASE_SIGNER_ADDRESS=self.signer_account.address,
            X402_RPC_URL="http://localhost:8545",
            X402_SIGNER_PRIVATE_KEY=self.signer_account.key.hex(),
            X402_SIGNER_ADDRESS=self.signer_account.address,
            X402_GAS_LIMIT=250000,
            X402_TX_TIMEOUT_SECONDS=10,
        )
        overrides.enable()
        self.addCleanup(overrides.disable)

        self.pay_to = pay_to
        self.usdc_contract = usdc_contract
        self.chain_id = 8453

    def _build_request_payload(self) -> dict:
        """Build a valid EVM Base payload with properly signed EIP-712 data."""
        now = int(timezone.now().timestamp())
        nonce_hex = HexBytes(os.urandom(32)).hex()

        authorization = {
            "from": self.payer_account.address,
            "to": self.pay_to,
            "value": "250000",
            "validAfter": str(now - 60),
            "validBefore": str(now + 600),
            "nonce": nonce_hex,
        }

        # Build EIP-712 typed data (same as BaseExactHandler.verify_signature)
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "TransferWithAuthorization": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "validAfter", "type": "uint256"},
                    {"name": "validBefore", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                ],
            },
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": self.chain_id,
                "verifyingContract": Web3.to_checksum_address(self.usdc_contract),
            },
            "message": {
                "from": Web3.to_checksum_address(self.payer_account.address),
                "to": Web3.to_checksum_address(self.pay_to),
                "value": int(authorization["value"]),
                "validAfter": int(authorization["validAfter"]),
                "validBefore": int(authorization["validBefore"]),
                "nonce": HexBytes(nonce_hex),
            },
        }

        signable = encode_typed_data(full_message=typed_data)
        signature = self.payer_account.sign_message(signable).signature.hex()

        # Raw dict payload for multichain views
        payment_payload = {
            "x402Version": 2,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "signature": signature,
                "authorization": authorization,
            },
        }

        payment_requirements = {
            "scheme": "exact",
            "network": "base",
            "amount": authorization["value"],
            "resource": "https://example.com/resource",
            "description": "Test order",
            "payTo": self.pay_to,
            "maxTimeoutSeconds": 600,
            "asset": self.usdc_contract,
            "extra": {
                "name": "USD Coin",
                "version": "2",
                "chainId": self.chain_id,
                "verifyingContract": self.usdc_contract,
            },
        }

        return {
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
        }

    def _successful_settlement(self, tx_hash: str = "0xabc123"):
        def settle(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            on_transaction_prepared(tx_hash)
            return SettlementResult(
                success=True,
                transaction_hash=tx_hash,
                payer=self.payer_account.address,
            )

        return settle

    def test_verify_persists_authorization(self):
        request_payload = self._build_request_payload()

        response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["isValid"])
        self.assertEqual(X402Authorization.objects.count(), 1)
        record = X402Authorization.objects.first()
        self.assertEqual(record.status, X402Authorization.Status.VERIFIED)
        self.assertEqual(body["payer"], record.payer)

    def test_verify_rejects_exact_underpayment(self):
        request_payload = self._build_request_payload()
        request_payload["paymentPayload"]["payload"]["authorization"]["value"] = "249999"

        response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["isValid"])
        self.assertIn("Amount mismatch", response.json()["invalidReason"])
        self.assertEqual(X402Authorization.objects.count(), 0)

    def test_verify_rejects_replay(self):
        request_payload = self._build_request_payload()

        first = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)

        second = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        body = second.json()
        self.assertFalse(body["isValid"])
        self.assertIn("nonce", body["invalidReason"].lower())
        self.assertEqual(X402Authorization.objects.count(), 1)

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_marks_authorization_settled(self, settle_mock):
        settle_mock.side_effect = self._successful_settlement()
        request_payload = self._build_request_payload()

        verify_response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertEqual(verify_response.status_code, 200)

        settle_response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(settle_response.status_code, 200)
        body = settle_response.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["transaction"], "0xabc123")

        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(record.transaction_hash, "0xabc123")
        settle_mock.assert_called_once()

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_requires_prior_verification(self, settle_mock):
        settle_mock.return_value = SettlementResult(success=True, transaction_hash="0xshould-not-submit")

        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(self._build_request_payload()),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["errorReason"], "Payment authorization was not verified.")
        settle_mock.assert_not_called()

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_fails_closed_when_authorization_db_is_unavailable(self, settle_mock):
        settle_mock.return_value = SettlementResult(success=True, transaction_hash="0xshould-not-submit")
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        with patch(
            "x402f.views_multichain.X402Authorization.objects.get",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = self.client.post(
                reverse("x402:settle"),
                data=json.dumps(request_payload),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["errorReason"], "Unable to load payment authorization.")
        settle_mock.assert_not_called()

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_is_idempotent_after_settled(self, settle_mock):
        settle_mock.side_effect = self._successful_settlement()
        request_payload = self._build_request_payload()

        verify_response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertEqual(verify_response.status_code, 200)

        first_settle = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertTrue(first_settle.json()["success"])

        second_settle = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        second_body = second_settle.json()
        self.assertEqual(second_settle.status_code, 200)
        self.assertTrue(second_body["success"])
        self.assertEqual(second_body["transaction"], "0xabc123")

        # Settlement is replay-safe: we should not submit another tx.
        settle_mock.assert_called_once()

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_persists_tx_hash_on_failure(self, settle_mock):
        settle_mock.return_value = SettlementResult(
            success=False,
            transaction_hash="0xpending",
            error_reason="Confirmation timed out",
        )
        request_payload = self._build_request_payload()

        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        settle_response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        body = settle_response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["transaction"], "0xpending")

        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertEqual(record.transaction_hash, "0xpending")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_mined_evm_failure_releases_authorization_claim(self, settle_mock):
        def fail_after_prepare(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            on_transaction_prepared("0xreverted")
            return SettlementResult(
                success=False,
                transaction_hash="0xreverted",
                error_reason="Transaction reverted on-chain",
                details={"transaction_status": "failed"},
            )

        settle_mock.side_effect = fail_after_prepare
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["transaction"], "0xreverted")
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.VERIFIED)
        self.assertIsNone(record.transaction_hash)
        self.assertIsNone(record.settling_started_at)
        self.assertIsNone(record.settled_amount)

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_stale_mined_failure_does_not_clear_newer_transaction(self, settle_mock):
        def fail_after_newer_claim(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            on_transaction_prepared("0xold")
            X402Authorization.objects.update(
                status=X402Authorization.Status.SETTLING,
                transaction_hash="0xnew",
                settling_started_at=timezone.now(),
            )
            return SettlementResult(
                success=False,
                transaction_hash="0xold",
                error_reason="Transaction reverted on-chain",
                details={"transaction_status": "failed"},
            )

        settle_mock.side_effect = fail_after_newer_claim
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["transaction"], "0xold")
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertEqual(record.transaction_hash, "0xnew")
        self.assertIsNotNone(record.settling_started_at)

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_definite_prebroadcast_rejection_marks_authorization_failed(self, settle_mock):
        settle_mock.return_value = SettlementResult(
            success=False,
            transaction_hash="0xnever-broadcast",
            error_reason="SEND_TRANSACTION_FAILED",
            details={"broadcast_status": "rejected"},
        )
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertIsNone(response.json()["transaction"])
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.FAILED)
        self.assertIsNone(record.transaction_hash)
        self.assertIsNone(record.settling_started_at)

    @patch(
        "x402f.chain_handlers.base_exact.BaseExactHandler.get_transaction_status",
        return_value=TransactionStatus.CONFIRMED,
    )
    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_pending_then_reconcile(self, settle_mock, check_mock):
        settle_mock.return_value = SettlementResult(
            success=False,
            transaction_hash="0xpending",
            error_reason="Confirmation timed out",
        )
        request_payload = self._build_request_payload()

        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        # First settle: tx submitted but confirmation pending
        first_settle = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertFalse(first_settle.json()["success"])

        # Second settle: reconcile by checking chain → marks settled
        second_settle = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        second_body = second_settle.json()
        self.assertTrue(second_body["success"])
        self.assertEqual(second_body["transaction"], "0xpending")

        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(record.transaction_hash, "0xpending")

        # settle_payment called only once; second call reconciled without re-submitting
        settle_mock.assert_called_once()
        check_mock.assert_called_once_with("0xpending")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.get_transaction_status")
    def test_stale_confirmed_reconcile_does_not_overwrite_newer_transaction(self, status_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        X402Authorization.objects.update(
            status=X402Authorization.Status.SETTLING,
            transaction_hash="0xold",
            settling_started_at=timezone.now(),
        )

        def replace_hash(_tx_hash):
            X402Authorization.objects.update(transaction_hash="0xnew")
            return TransactionStatus.CONFIRMED

        status_mock.side_effect = replace_hash
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["transaction"], "0xnew")
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertEqual(record.transaction_hash, "0xnew")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.get_transaction_status")
    def test_stale_failed_reconcile_does_not_clear_newer_transaction(self, status_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        X402Authorization.objects.update(
            status=X402Authorization.Status.SETTLING,
            transaction_hash="0xold",
            settling_started_at=timezone.now(),
        )

        def replace_hash(_tx_hash):
            X402Authorization.objects.update(transaction_hash="0xnew")
            return TransactionStatus.FAILED

        status_mock.side_effect = replace_hash
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["transaction"], "0xnew")
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertEqual(record.transaction_hash, "0xnew")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_in_progress_does_not_submit_again(self, settle_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        X402Authorization.objects.update(status=X402Authorization.Status.SETTLING)

        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["errorReason"], "Settlement is already in progress.")
        settle_mock.assert_not_called()

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settled_exact_replay_rejects_requirement_amount_mismatch(self, settle_mock):
        settle_mock.side_effect = self._successful_settlement("0xsettled")
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        first = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        self.assertTrue(first.json()["success"])

        request_payload["paymentRequirements"]["amount"] = "250001"
        replay = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertFalse(replay.json()["success"])
        self.assertEqual(replay.json()["errorReason"], "Payment requirement mismatch: amount")
        settle_mock.assert_called_once()

    @override_settings(X402_SETTLEMENT_LEASE_SECONDS=300)
    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_settle_reclaims_expired_hashless_claim(self, settle_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        X402Authorization.objects.update(
            status=X402Authorization.Status.SETTLING,
            settling_started_at=timezone.now() - timedelta(seconds=301),
        )

        def settle_with_prepared_hash(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            on_transaction_prepared("0xprepared")
            self.assertEqual(X402Authorization.objects.get().transaction_hash, "0xprepared")
            return SettlementResult(success=True, transaction_hash="0xprepared")

        settle_mock.side_effect = settle_with_prepared_hash
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertTrue(response.json()["success"])
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertIsNone(record.settling_started_at)

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_prepared_hash_survives_ambiguous_settlement_error(self, settle_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        def fail_after_prepare(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            on_transaction_prepared("0xambiguous")
            raise TimeoutError("RPC response lost")

        settle_mock.side_effect = fail_after_prepare
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 500)
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertEqual(record.transaction_hash, "0xambiguous")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_prepared_hash_persistence_conflict_returns_503(self, settle_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        def conflict_before_broadcast(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            X402Authorization.objects.update(transaction_hash="0xconflict")
            on_transaction_prepared("0xprepared")
            raise AssertionError("broadcast must not run")

        settle_mock.side_effect = conflict_before_broadcast
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["errorReason"], "Unable to persist prepared settlement transaction.")
        self.assertEqual(X402Authorization.objects.get().transaction_hash, "0xconflict")

    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_expired_claimant_cannot_persist_hash_into_newer_lease(self, settle_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        newer_lease = timezone.now() + timedelta(seconds=1)

        def stale_claimant(payload, requirements, on_transaction_prepared):  # noqa: ARG001
            X402Authorization.objects.update(
                status=X402Authorization.Status.SETTLING,
                transaction_hash=None,
                settling_started_at=newer_lease,
                settled_amount="newer",
            )
            on_transaction_prepared("0xstale")
            raise AssertionError("broadcast must not run after losing the lease")

        settle_mock.side_effect = stale_claimant
        response = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 503)
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLING)
        self.assertIsNone(record.transaction_hash)
        self.assertEqual(record.settling_started_at, newer_lease)
        self.assertEqual(record.settled_amount, "newer")

    @patch(
        "x402f.chain_handlers.base_exact.BaseExactHandler.get_transaction_status",
        side_effect=[TransactionStatus.PENDING, TransactionStatus.UNKNOWN],
    )
    @patch("x402f.chain_handlers.base_exact.BaseExactHandler.settle_payment")
    def test_pending_or_unknown_transaction_is_not_resubmitted(self, settle_mock, status_mock):
        request_payload = self._build_request_payload()
        self.client.post(
            reverse("x402:verify"),
            data=json.dumps(request_payload),
            content_type="application/json",
        )
        X402Authorization.objects.update(
            status=X402Authorization.Status.SETTLING,
            transaction_hash="0xpending",
            settling_started_at=timezone.now() - timedelta(seconds=600),
        )

        for _ in range(2):
            response = self.client.post(
                reverse("x402:settle"),
                data=json.dumps(request_payload),
                content_type="application/json",
            )
            self.assertEqual(response.json()["errorReason"], "Settlement transaction is pending confirmation.")

        settle_mock.assert_not_called()
        self.assertEqual(status_mock.call_count, 2)

    @override_settings(X402_SETTLE_TOKEN="settle-test-token")
    @patch(
        "x402f.chain_handlers.base_upto.BaseUptoHandler.get_transaction_status",
        return_value=TransactionStatus.CONFIRMED,
    )
    def test_upto_reconcile_preserves_and_binds_settled_amount(self, status_mock):
        payment_payload = {
            "x402Version": 2,
            "scheme": "upto",
            "network": "base",
            "payload": {
                "signature": "0xtest",
                "permit2Authorization": {"nonce": "42"},
            },
        }
        stored_requirements = {
            "scheme": "upto",
            "network": "base",
            "payTo": self.pay_to,
            "asset": self.usdc_contract,
            "maxAmountRequired": "1000",
        }
        X402Authorization.objects.create(
            nonce="upto:base:42",
            payer=self.payer_account.address,
            pay_to=self.pay_to,
            value="1000",
            valid_after=timezone.now(),
            valid_before=timezone.now() + timedelta(minutes=10),
            signature="0xtest",
            payment_requirements=stored_requirements,
            payment_payload=payment_payload,
            scheme="upto",
            status=X402Authorization.Status.SETTLING,
            transaction_hash="0xpending",
            settled_amount="100",
            settling_started_at=timezone.now(),
        )
        request_payload = {
            "paymentPayload": payment_payload,
            "paymentRequirements": {**stored_requirements, "amount": "100"},
        }

        reconciled = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
            HTTP_X_SETTLEMENT_TOKEN="settle-test-token",
        )

        self.assertTrue(reconciled.json()["success"])
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(record.settled_amount, "100")

        request_payload["paymentRequirements"]["amount"] = "101"
        replay = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(request_payload),
            content_type="application/json",
            HTTP_X_SETTLEMENT_TOKEN="settle-test-token",
        )

        self.assertFalse(replay.json()["success"])
        self.assertEqual(replay.json()["errorReason"], "Payment requirement mismatch: settled amount")
        status_mock.assert_called_once_with("0xpending")

    def test_supported_lists_networks(self):
        response = self.client.get(reverse("x402:supported"))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        kinds = body.get("kinds", [])
        networks = [k["network"] for k in kinds]
        self.assertIn("base", networks)
        self.assertIn("solana", networks)

    def test_signer_lock_canonicalizes_network_name(self):
        lock_ids = []

        class FakeCursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):  # noqa: ANN002
                return None

            def execute(self, sql, params):  # noqa: ARG002, ANN001
                lock_ids.append(params[0])

        class FakeConnection:
            vendor = "postgresql"

            def cursor(self):
                return FakeCursor()

        with patch("x402f.views_multichain.connection", FakeConnection()):
            with _signer_lock(" BASE "):
                pass
            with _signer_lock("base"):
                pass

        self.assertEqual(lock_ids[0], lock_ids[2])

    def test_well_known_returns_machine_readable_metadata(self):
        response = self.client.get("/.well-known/x402")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["version"], 1)
        self.assertEqual(body["resources"], [])
        self.assertEqual(body["facilitator"]["name"], "Ace Data Cloud Facilitator X402")
        self.assertEqual(body["facilitator"]["endpoints"]["verify"], "http://testserver/verify")
        self.assertIn(
            {"network": "base", "caip2": "eip155:8453"},
            body["facilitator"]["supportedNetworks"],
        )
        self.assertEqual(body["facilitator"]["addresses"]["base"], self.signer_account.address)

    def test_well_known_with_trailing_slash_returns_machine_readable_metadata(self):
        response = self.client.get("/.well-known/x402/")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["version"], 1)
        self.assertEqual(body["facilitator"]["endpoints"]["settle"], "http://testserver/settle")
