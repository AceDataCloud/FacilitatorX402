import json
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from x402f.models import X402Authorization
from x402f.tests.test_official_views import _request_body, _upto_request_body
from x402f.views_official import SettleRequest, _parse_request, _payment_identity


@override_settings(X402_SETTLE_TOKEN="internal-secret")
class SettlementStatusTests(TestCase):
    def create_record(self, body, state="settled", amount="250000"):
        identity = _payment_identity(_parse_request(body, SettleRequest))
        return X402Authorization.objects.create(
            nonce=identity.nonce,
            payer=identity.payer,
            pay_to=body["paymentRequirements"]["payTo"],
            value=body["paymentRequirements"]["amount"],
            valid_after=identity.valid_after,
            valid_before=identity.valid_before,
            signature=identity.signature,
            payment_requirements=body["paymentRequirements"],
            payment_payload=body["paymentPayload"],
            scheme=body["paymentRequirements"]["scheme"],
            status=state,
            transaction_hash="original-tx",
            settled_amount=amount,
        )

    def lookup(self, body, token="internal-secret"):
        return self.client.post(
            reverse("x402:settlement-status"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_SETTLEMENT_TOKEN=token,
        )

    @override_settings(X402_BASE_EXACT_ENABLED=False)
    def test_read_disabled_rail_without_signer_or_state_mutation(self):
        body = _request_body()
        row = self.create_record(body, amount=body["paymentRequirements"]["amount"])
        before = X402Authorization.objects.values().get(pk=row.pk)
        with patch("x402f.views_official._configured") as configured:
            response = self.lookup(body)
        configured.assert_not_called()
        assert response.status_code == 200
        assert response.json()["authorizationStatus"] == "settled"
        assert response.json()["transaction"] == "original-tx"
        assert response.json()["amount"] == body["paymentRequirements"]["amount"]
        assert X402Authorization.objects.values().get(pk=row.pk) == before

    def test_lookup_requires_internal_auth_and_matching_payload(self):
        body = _request_body()
        self.create_record(body)
        assert self.lookup(body, token="").status_code == 403
        body["paymentPayload"]["payload"]["signature"] = "0x" + "33" * 65
        assert self.lookup(body).status_code == 409

    def test_settling_is_unknown_payment_not_success(self):
        body = _request_body()
        self.create_record(body, state="settling")
        response = self.lookup(body)
        assert response.json()["authorizationStatus"] == "settling"
        assert response.json()["success"] is False

    def test_upto_cannot_change_amount_after_claim(self):
        body = _upto_request_body(_request_body())
        self.create_record(body, state="settling", amount="500")
        assert self.lookup(body).status_code == 409
        body["paymentRequirements"]["amount"] = "500"
        assert self.lookup(body).status_code == 200

    def test_solana_receipt_lookup_preserves_duplicate_settle_rejection(self):
        body = _request_body()
        network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
        body["paymentRequirements"].update(network=network, asset="mint", payTo="payee")
        body["paymentPayload"]["accepted"].update(network=network, asset="mint", payTo="payee")
        body["paymentPayload"]["payload"] = {"transaction": "synthetic-transaction"}
        with (
            patch("x402f.views_official.decode_transaction_from_payload", return_value=SimpleNamespace()),
            patch("x402f.views_official.transaction_message_hash", return_value="synthetic-message-hash"),
            patch("x402f.views_official.get_token_payer_from_transaction", return_value="synthetic-payer"),
            override_settings(X402_SOLANA_MAINNET_ENABLED=True, X402_SOLANA_ASSET="mint", X402_SOLANA_PAY_TO="payee"),
        ):
            self.create_record(body, amount=body["paymentRequirements"]["amount"])
            receipt = self.lookup(body)
            duplicate = self.client.post(
                reverse("x402:settle"),
                data=json.dumps(body),
                content_type="application/json",
                HTTP_X_SETTLEMENT_TOKEN="internal-secret",
            )
        assert receipt.json()["success"] is True
        assert receipt.json()["transaction"] == "original-tx"
        assert duplicate.json()["success"] is False
        assert duplicate.json()["transaction"] == ""
