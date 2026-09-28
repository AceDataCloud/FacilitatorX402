import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from django.urls import reverse
from x402.schemas import VerifyResponse

from x402f.models import EnvarDelegationAuthorization, EnvarDelegationRegistration, X402Authorization
from x402f.tests.test_envar_verify import EnvarVerifyTests
from x402f.tests.test_official_views import FakeFacilitator, FakeSigner


class EnvarSettleTests(EnvarVerifyTests):
    def settle(self, payment, *, intent=None, token="envar-secret"):
        return self.client.post(
            reverse("x402:envar-delegation-settle"),
            data=json.dumps({"intent_id": str(intent or self.registration.intent_id), "payment": payment}),
            content_type="application/json",
            HTTP_X_ENVAR_DELEGATION_TOKEN=token,
        )

    def reserve(self, payment):
        with patch("x402f.delegation_verify._configured") as configured:
            configured.return_value.facilitator.verify.return_value = VerifyResponse(
                is_valid=True, payer=self.payer.address
            )
            response = self.verify(payment)
        assert response.json()["isValid"] is True, response.content
        return X402Authorization.objects.get()

    def configured(self, network=None, on_transaction_prepared=None, on_transaction_broadcast=None):
        del on_transaction_broadcast, network
        signer = FakeSigner()
        signer.has_exact_usdc_transfer = lambda _tx, _asset, _payer, _recipient, _amount: True
        return SimpleNamespace(facilitator=FakeFacilitator(on_transaction_prepared), signer_for=lambda _network: signer)

    def test_settles_once_and_replays_same_confirmed_transaction(self):
        payment = self.payment()
        record = self.reserve(payment)
        with (
            patch("x402f.views_official._configured", side_effect=self.configured) as configured,
            patch("x402f.delegation_settle._configured", side_effect=self.configured),
        ):
            first = self.settle(payment)
            second = self.settle(payment)
        assert first.json()["success"] is True, first.content
        assert second.json()["success"] is True
        assert first.json()["transaction"] == second.json()["transaction"]
        assert configured.call_count == 1
        record.refresh_from_db()
        assert record.status == X402Authorization.Status.SETTLED
        assert record.settled_amount == "10000"
        assert EnvarDelegationAuthorization.objects.count() == 1

    def test_wrong_intent_payload_and_token_never_broadcast(self):
        payment = self.payment()
        self.reserve(payment)
        changed = json.loads(json.dumps(payment))
        changed["paymentPayload"]["payload"]["signature"] = "0x" + "11" * 65
        other = EnvarDelegationRegistration.objects.create(
            intent_id=uuid.uuid4(),
            parent_run_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            request_owner_account_id="buyer",
            agent_id=self.registration.agent_id,
            owner_account_id="seller",
            agent_version_id=self.registration.agent_version_id,
            payee_revision=1,
            recipient=self.registration.recipient,
            network="eip155:8453",
            asset=self.registration.asset,
            amount_atomic="10000",
            terms_digest="a" * 64,
            expires_at=self.registration.expires_at,
        )
        with patch("x402f.views_official._configured") as configured:
            assert self.settle(payment, intent=other.intent_id).json()["success"] is False
            assert self.settle(changed).json()["success"] is False
            assert self.settle(payment, token="wrong").status_code == 403
            ordinary = self.client.post(
                reverse("x402:settle"),
                data=json.dumps(payment),
                content_type="application/json",
                HTTP_X_SETTLEMENT_TOKEN="internal-secret",
            )
            assert ordinary.json()["success"] is False
            configured.assert_not_called()
        assert X402Authorization.objects.get().status == X402Authorization.Status.VERIFIED

    def test_prepared_transaction_reconciles_same_hash_without_new_settle(self):
        payment = self.payment()
        record = self.reserve(payment)
        tx_hash = "0x" + "cd" * 32
        X402Authorization.objects.filter(pk=record.pk).update(
            status=X402Authorization.Status.SETTLING,
            transaction_hash=tx_hash,
            prepared_transaction="prepared-transaction",
        )

        class PendingSigner(FakeSigner):
            def get_transaction_status(self, _tx_hash):
                assert _tx_hash == tx_hash
                return "pending"

            def broadcast_prepared(self, raw):
                assert raw == "prepared-transaction"
                return tx_hash

        with (
            patch("x402f.views_official._configured") as configured,
            patch("x402f.delegation_settle._configured", side_effect=self.configured),
        ):
            configured.return_value.signer_for.return_value = PendingSigner()
            pending = self.settle(payment)
            assert pending.json()["success"] is False
            assert pending.json()["transaction"] == tx_hash
            configured.return_value.facilitator.settle.assert_not_called()
            proven = FakeSigner()
            proven.has_exact_usdc_transfer = lambda _tx, _asset, _payer, _recipient, _amount: True
            configured.return_value.signer_for.return_value = proven
            confirmed = self.settle(payment)
            configured.return_value.facilitator.settle.assert_not_called()
        assert confirmed.json()["success"] is True
        assert confirmed.json()["transaction"] == tx_hash
        record.refresh_from_db()
        assert record.status == X402Authorization.Status.SETTLED

    def test_missing_transfer_proof_never_reports_success(self):
        payment = self.payment()
        record = self.reserve(payment)
        with (
            patch("x402f.views_official._configured", side_effect=self.configured),
            patch("x402f.delegation_settle._configured") as proof,
        ):
            proof.return_value.signer_for.return_value.has_exact_usdc_transfer.return_value = False
            response = self.settle(payment)
        assert response.json()["success"] is False
        assert response.json()["transaction"] == "0x" + "ab" * 32
        record.refresh_from_db()
        assert record.status == X402Authorization.Status.SETTLED
