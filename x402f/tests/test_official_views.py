import json
import threading
import time
from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from x402.schemas import SettleResponse, VerifyResponse

from core.views import build_well_known_x402_data
from x402f.models import X402Authorization
from x402f.tests.test_official_facilitator import _payment
from x402f.views_official import _payment_identity, _seed_signer_nonce, _signer_lock, _validate_policy


class FakeSigner:
    def get_transaction_status(self, _tx_hash: str) -> str:
        return "confirmed"


class FakeFacilitator:
    def __init__(self, on_transaction_prepared=None) -> None:
        self.on_transaction_prepared = on_transaction_prepared

    def verify(self, payload, requirements):  # noqa: ANN001, ANN201
        authorization = payload.payload.get("authorization") or payload.payload.get("permit2Authorization")
        return VerifyResponse(
            is_valid=True,
            payer=authorization["from"],
        )

    def settle(self, payload, requirements):  # noqa: ANN001, ANN201
        tx_hash = "0x" + "ab" * 32
        assert self.on_transaction_prepared is not None
        if requirements.scheme == "upto":
            assert X402Authorization.objects.get().settled_amount == requirements.amount
        self.on_transaction_prepared(tx_hash, "deadbeef", 7)
        record = X402Authorization.objects.get()
        assert record.status == X402Authorization.Status.SETTLING
        assert record.transaction_hash == tx_hash
        assert record.prepared_transaction == "deadbeef"
        assert record.signer_nonce == 7
        return SettleResponse(
            success=True,
            payer=(payload.payload.get("authorization") or payload.payload.get("permit2Authorization"))["from"],
            transaction=tx_hash,
            network=str(requirements.network),
            amount=requirements.amount,
        )


def _request_body() -> dict:
    payload, requirements = _payment()
    return {
        "x402Version": 2,
        "paymentPayload": payload.model_dump(mode="json", by_alias=True),
        "paymentRequirements": requirements.model_dump(mode="json", by_alias=True),
    }


def _upto_request_body(body: dict) -> dict:
    amount = "1000"
    payer = body["paymentPayload"]["payload"]["authorization"]["from"]
    pay_to = body["paymentRequirements"]["payTo"]
    asset = body["paymentRequirements"]["asset"]
    accepted = body["paymentPayload"]["accepted"]
    accepted.update({"scheme": "upto", "amount": amount})
    body["paymentRequirements"].update({"scheme": "upto", "amount": amount})
    body["paymentPayload"]["payload"] = {
        "permit2Authorization": {
            "from": payer,
            "permitted": {"token": asset, "amount": amount},
            "spender": "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002",
            "nonce": "42",
            "deadline": str(int(time.time()) + 600),
            "witness": {"to": pay_to, "facilitator": body["paymentRequirements"]["payTo"], "validAfter": "0"},
        },
        "signature": "0x" + "11" * 65,
    }
    return body


@override_settings(
    X402_BASE_ASSET="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
    X402_SETTLE_TOKEN="internal-secret",
)
class OfficialViewTests(TestCase):
    def _facilitator_factory(  # noqa: ANN201
        self,
        on_transaction_prepared=None,  # noqa: ANN001
        on_transaction_broadcast=None,  # noqa: ANN001
        network=None,  # noqa: ANN001
    ):
        del on_transaction_broadcast
        del network
        return FakeFacilitator(on_transaction_prepared), FakeSigner()

    def setUp(self) -> None:
        self.body = _request_body()
        pay_to = self.body["paymentRequirements"]["payTo"]
        self.settings_override = override_settings(X402_BASE_PAY_TO=pay_to)
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    def _settle(self, body):  # noqa: ANN001, ANN201
        return self.client.post(
            reverse("x402:settle"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_SETTLEMENT_TOKEN="internal-secret",
        )

    @override_settings(X402_BASE_NETWORK="eip155:84532")
    def test_discovery_uses_configured_sepolia_network(self) -> None:
        data = build_well_known_x402_data("https://facilitator2.acedata.cloud")

        self.assertEqual(
            data["facilitator"]["supportedKinds"],
            [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}],
        )

    @override_settings(
        X402_BASE_NETWORK="eip155:8453",
        X402_BASE_EXACT_ENABLED=True,
        X402_BASE_UPTO_ENABLED=True,
        X402_SKALE_EXACT_ENABLED=True,
        X402_SOLANA_MAINNET_ENABLED=True,
        X402_SOLANA_DEVNET_ENABLED=True,
    )
    def test_well_known_advertises_all_enabled_parity_kinds(self) -> None:
        data = build_well_known_x402_data("https://facilitator2.acedata.cloud")
        kinds = {(item["scheme"], item["network"]) for item in data["facilitator"]["supportedKinds"]}
        self.assertEqual(
            kinds,
            {
                ("exact", "eip155:8453"),
                ("upto", "eip155:8453"),
                ("exact", "eip155:1187947933"),
                ("exact", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
                ("exact", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
            },
        )

    @override_settings(
        X402_BASE_EXACT_ENABLED=True,
        X402_BASE_SIGNER_ADDRESS="0x1111111111111111111111111111111111111111",
        X402_BASE_UPTO_ENABLED=False,
        X402_SKALE_EXACT_ENABLED=False,
        X402_SOLANA_MAINNET_ENABLED=False,
        X402_SOLANA_DEVNET_ENABLED=False,
    )
    @patch("x402f.official._evm_signer", side_effect=RuntimeError("RPC unavailable"))
    def test_supported_does_not_contact_rpc(self, _builder) -> None:
        response = self.client.get(reverse("x402:supported"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["kinds"][0]["network"], "eip155:8453")

    @override_settings(
        X402_SOLANA_MAINNET_ENABLED=True,
        X402_SOLANA_ASSET="AbCd",
        X402_SOLANA_PAY_TO="PayTo",
    )
    def test_solana_policy_is_case_sensitive(self) -> None:
        requirements = SimpleNamespace(
            network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            scheme="exact",
            asset="abcd",
            pay_to="PayTo",
        )
        with self.assertRaisesRegex(ValueError, "asset"):
            _validate_policy(SimpleNamespace(payment_requirements=requirements))
        requirements.asset = "AbCd"
        requirements.pay_to = "payto"
        with self.assertRaisesRegex(ValueError, "recipient"):
            _validate_policy(SimpleNamespace(payment_requirements=requirements))

    def test_verify_rejects_legacy_request_shape(self) -> None:
        response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps({"paymentPayload": {"scheme": "exact", "network": "base"}}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["isValid"])
        self.assertEqual(X402Authorization.objects.count(), 0)

    def test_verify_rejects_hybrid_permit2_payload(self) -> None:
        body = self.body
        body["paymentPayload"]["payload"]["permit2Authorization"] = {"nonce": "1"}

        response = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(body),
            content_type="application/json",
        )

        self.assertFalse(response.json()["isValid"])
        self.assertIn("EIP-3009", response.json()["invalidReason"])

    def test_settle_authentication_failures_use_official_response_schema(self) -> None:
        for headers in ({}, {"HTTP_X_SETTLEMENT_TOKEN": "wrong-secret"}):
            response = self.client.post(
                reverse("x402:settle"),
                data=json.dumps(self.body),
                content_type="application/json",
                **headers,
            )

            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                response.json(),
                {
                    "success": False,
                    "errorReason": "Unauthorized settlement caller.",
                    "transaction": "",
                    "network": "eip155:8453",
                },
            )

    @patch("x402f.views_official.build_configured_facilitator")
    def test_verify_reserves_official_authorization_and_accepts_identical_retry(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body

        first = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_IDEMPOTENCY_KEY="retry-1",
        )
        second = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_IDEMPOTENCY_KEY="retry-1",
        )

        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["isValid"])
        self.assertTrue(second.json()["isValid"])
        self.assertEqual(X402Authorization.objects.count(), 1)
        record = X402Authorization.objects.get()
        self.assertEqual(record.payment_requirements["network"], "eip155:8453")
        self.assertEqual(record.payment_payload["accepted"]["network"], "eip155:8453")
        self.assertEqual(record.verification_id, "retry-1")

    @patch("x402f.views_official.build_configured_facilitator")
    def test_identical_verify_without_idempotency_key_is_not_reused(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        first = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        second = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")

        self.assertTrue(first.json()["isValid"])
        self.assertFalse(second.json()["isValid"])
        self.assertIn("conflicts", second.json()["invalidReason"])

    @patch("x402f.views_official.build_configured_facilitator")
    def test_identical_verify_retry_uses_reservation_when_facilitator_is_unavailable(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        first = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_IDEMPOTENCY_KEY="retry-unavailable",
        )
        self.assertTrue(first.json()["isValid"])

        factory.side_effect = RuntimeError("RPC unavailable")
        second = self.client.post(
            reverse("x402:verify"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_IDEMPOTENCY_KEY="retry-unavailable",
        )

        self.assertFalse(second.json()["isValid"])
        self.assertEqual(second.json()["invalidReason"], "Unable to revalidate reserved payment authorization.")
        self.assertEqual(factory.call_count, 2)

    @patch("x402f.views_official.build_configured_facilitator")
    def test_verify_rejects_identical_authorization_after_settlement(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        first = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(first.json()["isValid"])
        X402Authorization.objects.update(status=X402Authorization.Status.SETTLED)

        second = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")

        self.assertFalse(second.json()["isValid"])
        self.assertIn("conflicts", second.json()["invalidReason"])

    def test_sqlite_signer_lock_serializes_same_network(self) -> None:
        active = 0
        maximum_active = 0
        state_lock = threading.Lock()

        def worker() -> None:
            nonlocal active, maximum_active
            with _signer_lock("eip155:84532"):
                with state_lock:
                    active += 1
                    maximum_active = max(maximum_active, active)
                time.sleep(0.03)
                with state_lock:
                    active -= 1

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=1)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(maximum_active, 1)

    @patch("x402f.views_official.build_configured_facilitator")
    def test_verify_rejects_same_nonce_with_changed_requirements(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        first = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(first.json()["isValid"])

        body["paymentRequirements"]["amount"] = str(int(body["paymentRequirements"]["amount"]) + 1)
        second = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")

        self.assertFalse(second.json()["isValid"])
        self.assertEqual(second.json()["invalidReason"], "Authorization nonce conflicts with a different payment.")
        self.assertEqual(X402Authorization.objects.count(), 1)

    @override_settings(X402_BASE_UPTO_ENABLED=True)
    @patch("x402f.views_official._signer_lock", return_value=nullcontext())
    @patch("x402f.views_official.build_configured_facilitator")
    def test_upto_settlement_allows_actual_below_ceiling_and_rejects_excess(self, factory, _lock) -> None:
        factory.side_effect = self._facilitator_factory
        body = _upto_request_body(self.body)
        verify = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(verify.json()["isValid"])
        record = X402Authorization.objects.get()
        self.assertEqual(record.scheme, "upto")
        self.assertEqual(record.value, "1000")

        body["paymentRequirements"]["amount"] = "250"
        settled = self._settle(body)
        self.assertTrue(settled.json()["success"])
        record.refresh_from_db()
        self.assertEqual(record.settled_amount, "250")

        body["paymentRequirements"]["amount"] = "1001"
        rejected = self._settle(body)
        self.assertFalse(rejected.json()["success"])
        self.assertEqual(rejected.json()["errorReason"], "Payment payload or requirements do not match verification.")

    def test_evm_signer_nonce_seed_is_scoped_by_network(self) -> None:
        X402Authorization.objects.create(
            nonce="base",
            payer="payer",
            pay_to="payee",
            value="1",
            valid_after=timezone.now(),
            valid_before=timezone.now() + timedelta(minutes=1),
            signature="signature",
            payment_requirements={"network": "eip155:8453"},
            payment_payload={},
            status=X402Authorization.Status.SETTLING,
            signer_nonce=7,
        )
        X402Authorization.objects.create(
            nonce="skale",
            payer="payer",
            pay_to="payee",
            value="1",
            valid_after=timezone.now(),
            valid_before=timezone.now() + timedelta(minutes=1),
            signature="signature",
            payment_requirements={"network": "eip155:1187947933"},
            payment_payload={},
            status=X402Authorization.Status.SETTLING,
            signer_nonce=1000,
        )
        signer = SimpleNamespace(_reserve_nonce=Mock(), _next_nonce=0)

        _seed_signer_nonce(signer, "eip155:8453")

        self.assertEqual(signer._next_nonce, 8)

    @patch("x402f.views_official.get_token_payer_from_transaction", return_value="payer-address")
    @patch("x402f.views_official.transaction_message_hash", return_value="message-hash")
    @patch("x402f.views_official.decode_transaction_from_payload", return_value=SimpleNamespace())
    def test_svm_identity_uses_official_message_hash(self, _decode, _message_hash, _payer) -> None:
        request_model = SimpleNamespace(
            payment_payload=SimpleNamespace(payload={"transaction": "base64-transaction"}),
            payment_requirements=SimpleNamespace(
                network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                scheme="exact",
                asset="mint",
                max_timeout_seconds=60,
            ),
        )

        identity = _payment_identity(request_model)

        self.assertEqual(identity.nonce, "svm:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:message-hash")
        self.assertEqual(identity.payer, "payer-address")

    @patch("x402f.views_official._signer_lock", return_value=nullcontext())
    @patch("x402f.views_official.build_configured_facilitator")
    def test_settle_persists_hash_before_broadcast_result_and_replays(self, factory, _lock) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        verify = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(verify.json()["isValid"])

        first = self._settle(body)
        second = self._settle(body)

        self.assertTrue(first.json()["success"])
        self.assertTrue(second.json()["success"])
        self.assertEqual(first.json()["transaction"], second.json()["transaction"])
        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(factory.call_count, 2)

    def test_settled_solana_payment_rejects_duplicate_settlement(self) -> None:
        body = self.body
        network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
        body["paymentPayload"]["accepted"]["network"] = network
        body["paymentRequirements"]["network"] = network
        body["paymentRequirements"]["asset"] = "mint"
        body["paymentRequirements"]["payTo"] = "payee"
        body["paymentPayload"]["payload"] = {"transaction": "base64-transaction"}
        X402Authorization.objects.create(
            nonce=f"svm:{network}:message-hash",
            payer="payer-address",
            pay_to="payee",
            value="1",
            valid_after=timezone.now(),
            valid_before=timezone.now() + timedelta(minutes=1),
            signature="payload-hash",
            payment_requirements=body["paymentRequirements"],
            payment_payload=body["paymentPayload"],
            scheme="exact",
            status=X402Authorization.Status.SETTLED,
            transaction_hash="solana-signature",
            settled_amount="1",
        )

        with (
            override_settings(
                X402_SOLANA_MAINNET_ENABLED=True,
                X402_SOLANA_ASSET="mint",
                X402_SOLANA_PAY_TO="payee",
            ),
            patch("x402f.views_official.decode_transaction_from_payload", return_value=SimpleNamespace()),
            patch("x402f.views_official.transaction_message_hash", return_value="message-hash"),
            patch("x402f.views_official.get_token_payer_from_transaction", return_value="payer-address"),
            patch("x402f.views_official.hashlib.sha256") as sha256,
        ):
            sha256.return_value.hexdigest.return_value = "payload-hash"
            response = self._settle(body)

        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["errorReason"], "duplicate_settlement")
        self.assertEqual(response.json()["transaction"], "")

    @patch("x402f.views_official.build_configured_facilitator")
    def test_settle_rejects_payload_changed_after_verify(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        verify = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(verify.json()["isValid"])
        body["paymentRequirements"]["amount"] = "250001"

        response = self._settle(body)

        self.assertFalse(response.json()["success"])
        self.assertEqual(
            response.json()["errorReason"],
            "Payment payload or requirements do not match verification.",
        )

    @patch("x402f.views_official.build_configured_facilitator")
    def test_confirmed_reconciliation_returns_receipt_when_final_db_write_fails(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        verify = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(verify.json()["isValid"])
        record = X402Authorization.objects.get()
        record.status = X402Authorization.Status.SETTLING
        record.transaction_hash = "0x" + "ab" * 32
        record.save(update_fields=["status", "transaction_hash"])

        factory.side_effect = None
        factory.return_value = (SimpleNamespace(), FakeSigner())
        with patch("x402f.views_official.X402Authorization.objects.filter") as filtered:
            filtered.return_value.update.side_effect = RuntimeError("database unavailable")
            response = self._settle(body)

        self.assertTrue(response.json()["success"])
        self.assertEqual(response.json()["transaction"], record.transaction_hash)
