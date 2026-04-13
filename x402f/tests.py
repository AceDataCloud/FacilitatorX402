import json
import os
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from web3 import Web3

from x402f.chain_handlers.base import SettlementResult
from x402f.models import X402Authorization


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

        # Build EIP-712 typed data (same as BaseChainHandler.verify_signature)
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
            "amount": "1000000",
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

    @patch("x402f.chain_handlers.base_chain.BaseChainHandler.settle_payment")
    def test_settle_marks_authorization_settled(self, settle_mock):
        settle_mock.return_value = SettlementResult(
            success=True,
            transaction_hash="0xabc123",
            payer=self.payer_account.address,
        )
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

    @patch("x402f.chain_handlers.base_chain.BaseChainHandler.settle_payment")
    def test_settle_is_idempotent_after_settled(self, settle_mock):
        settle_mock.return_value = SettlementResult(
            success=True,
            transaction_hash="0xabc123",
            payer=self.payer_account.address,
        )
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

    @patch("x402f.chain_handlers.base_chain.BaseChainHandler.settle_payment")
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
        self.assertEqual(record.status, X402Authorization.Status.VERIFIED)
        self.assertEqual(record.transaction_hash, "0xpending")

    @patch("x402f.chain_handlers.base_chain.BaseChainHandler.check_transaction_status", return_value=True)
    @patch("x402f.chain_handlers.base_chain.BaseChainHandler.settle_payment")
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

    def test_supported_lists_networks(self):
        response = self.client.get(reverse("x402:supported"))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        kinds = body.get("kinds", [])
        networks = [k["network"] for k in kinds]
        self.assertIn("base", networks)
        self.assertIn("solana", networks)

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
