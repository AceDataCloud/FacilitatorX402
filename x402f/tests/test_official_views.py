import json
import threading
import time
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from x402.schemas import SettleResponse, VerifyResponse

from core.views import build_well_known_x402_data
from x402f.models import X402Authorization
from x402f.tests.test_official_facilitator import _payment
from x402f.views_official import _signer_lock


class FakeSigner:
    def get_transaction_status(self, _tx_hash: str) -> str:
        return "confirmed"


class FakeFacilitator:
    def __init__(self, on_transaction_prepared=None) -> None:
        self.on_transaction_prepared = on_transaction_prepared

    def verify(self, payload, requirements):  # noqa: ANN001, ANN201
        return VerifyResponse(
            is_valid=True,
            payer=payload.payload["authorization"]["from"],
        )

    def settle(self, payload, requirements):  # noqa: ANN001, ANN201
        tx_hash = "0x" + "ab" * 32
        assert self.on_transaction_prepared is not None
        self.on_transaction_prepared(tx_hash, "deadbeef", 7)
        record = X402Authorization.objects.get()
        assert record.status == X402Authorization.Status.SETTLING
        assert record.transaction_hash == tx_hash
        assert record.prepared_transaction == "deadbeef"
        assert record.signer_nonce == 7
        return SettleResponse(
            success=True,
            payer=payload.payload["authorization"]["from"],
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


@override_settings(
    X402_BASE_ASSET="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
    X402_SETTLE_TOKEN="internal-secret",
)
class OfficialViewTests(TestCase):
    def _facilitator_factory(self, on_transaction_prepared=None, on_transaction_broadcast=None):  # noqa: ANN001, ANN201
        del on_transaction_broadcast
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

    @patch("x402f.views_official.build_configured_facilitator")
    def test_verify_reserves_official_authorization_and_accepts_identical_retry(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body

        first = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        second = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")

        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["isValid"])
        self.assertTrue(second.json()["isValid"])
        self.assertEqual(X402Authorization.objects.count(), 1)
        record = X402Authorization.objects.get()
        self.assertEqual(record.payment_requirements["network"], "eip155:8453")
        self.assertEqual(record.payment_payload["accepted"]["network"], "eip155:8453")

    @patch("x402f.views_official.build_configured_facilitator")
    def test_identical_verify_retry_uses_reservation_when_facilitator_is_unavailable(self, factory) -> None:
        factory.side_effect = self._facilitator_factory
        body = self.body
        first = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        self.assertTrue(first.json()["isValid"])

        factory.side_effect = RuntimeError("RPC unavailable")
        second = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")

        self.assertTrue(second.json()["isValid"])
        self.assertEqual(second.json()["payer"].lower(), X402Authorization.objects.get().payer.lower())
        self.assertEqual(factory.call_count, 1)

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
