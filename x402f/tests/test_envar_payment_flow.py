import hashlib
import json
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from x402.schemas import VerifyResponse

from x402f.models import EnvarDelegationAuthorization, EnvarDelegationRegistration, X402Authorization
from x402f.tests import test_envar_settle as settle_helpers
from x402f.tests import test_envar_verify as verify_helpers
from x402f.tests.test_official_facilitator import USDC_BASE


@override_settings(
    X402_ENVAR_DELEGATION_ENABLED=True,
    X402_ENVAR_DELEGATION_TOKEN="envar-secret",
    X402_BASE_NETWORK="eip155:8453",
    X402_BASE_ASSET=USDC_BASE,
    X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
)
class EnvarPaymentFlowTests(TestCase):
    setUp = verify_helpers.EnvarVerifyTests.setUp
    payment = verify_helpers.EnvarVerifyTests.payment
    verify = verify_helpers.EnvarVerifyTests.verify
    settle = settle_helpers.EnvarSettleTests.settle
    configured = settle_helpers.EnvarSettleTests.configured

    def test_registered_signed_intent_verifies_settles_and_replays_one_tx(self):
        registration = self.registration
        payload = {
            "intent_id": str(registration.intent_id),
            "parent_run_id": str(registration.parent_run_id),
            "attempt_id": str(registration.attempt_id),
            "request_owner_account_id": registration.request_owner_account_id,
            "agent_id": str(registration.agent_id),
            "owner_account_id": registration.owner_account_id,
            "agent_version_id": str(registration.agent_version_id),
            "payee_revision": registration.payee_revision,
            "recipient": registration.recipient,
            "network": registration.network,
            "asset": registration.asset,
            "amount_atomic": registration.amount_atomic,
            "terms_digest": registration.terms_digest,
            "expires_at": registration.expires_at.isoformat(),
        }
        # Reuse the same registration ID: a replay is accepted without creating a second record.
        response = self.client.post(
            reverse("x402:envar-delegation-register"),
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_ENVAR_DELEGATION_TOKEN="envar-secret",
        )
        assert response.status_code == 200 and EnvarDelegationRegistration.objects.count() == 1
        payment = self.payment()
        nonce = "0x" + hashlib.sha256(b"envar-delegation-payment-v1:" + registration.intent_id.bytes).hexdigest()
        assert payment["paymentPayload"]["payload"]["authorization"]["nonce"] == nonce
        with patch("x402f.delegation_verify._configured") as configured:
            configured.return_value.facilitator.verify.return_value = VerifyResponse(
                is_valid=True, payer=self.payer.address
            )
            assert self.verify(payment).json()["isValid"] is True
        with (
            patch("x402f.views_official._configured", side_effect=self.configured) as settle_config,
            patch("x402f.delegation_settle._configured", side_effect=self.configured),
        ):
            first = self.settle(payment)
            second = self.settle(payment)
        assert first.json()["success"] is True and second.json()["success"] is True
        assert first.json()["transaction"] == second.json()["transaction"]
        assert settle_config.call_count == 1
        assert X402Authorization.objects.count() == 1
        assert EnvarDelegationAuthorization.objects.count() == 1
        assert X402Authorization.objects.get().status == X402Authorization.Status.SETTLED
