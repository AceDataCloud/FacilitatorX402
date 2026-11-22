import json
import uuid
from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from x402f.models import EnvarDelegationRegistration
from x402f.tests.test_official_views import _request_body


class EnvarRegistrationTests(TestCase):
    def setUp(self):
        self.url = reverse("x402:envar-delegation-register")
        self.terms = {
            "intent_id": str(uuid.uuid4()),
            "parent_run_id": str(uuid.uuid4()),
            "attempt_id": str(uuid.uuid4()),
            "request_owner_account_id": "buyer",
            "agent_id": str(uuid.uuid4()),
            "owner_account_id": "seller",
            "agent_version_id": str(uuid.uuid4()),
            "payee_revision": 2,
            "recipient": "0x2222222222222222222222222222222222222222",
            "network": "eip155:8453",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "amount_atomic": "10000",
            "terms_digest": "a" * 64,
            "expires_at": (timezone.now() + timedelta(minutes=10)).isoformat(),
        }

    def register(self, terms=None, token="envar-secret"):
        return self.client.post(
            self.url,
            data=json.dumps(terms or self.terms),
            content_type="application/json",
            HTTP_X_ENVAR_DELEGATION_TOKEN=token,
        )

    def test_default_disabled_and_separate_token(self):
        assert self.register().status_code == 403
        with override_settings(X402_ENVAR_DELEGATION_ENABLED=True, X402_ENVAR_DELEGATION_TOKEN="envar-secret"):
            assert self.register(token="").status_code == 403
            assert self.register(token="other").status_code == 403
            assert self.register(token="internal-secret").status_code == 403
        assert not EnvarDelegationRegistration.objects.exists()

    @override_settings(X402_ENVAR_DELEGATION_ENABLED=True, X402_ENVAR_DELEGATION_TOKEN="envar-secret")
    def test_registration_is_idempotent_and_conflicting_terms_fail(self):
        first = self.register()
        assert first.status_code == 201 and first["Cache-Control"] == "no-store"
        assert self.register().status_code == 200
        changed = {**self.terms, "recipient": "0x3333333333333333333333333333333333333333"}
        assert self.register(changed).status_code == 409
        for field, value in (
            ("parent_run_id", str(uuid.uuid4())),
            ("attempt_id", str(uuid.uuid4())),
            ("request_owner_account_id", "different-buyer"),
        ):
            assert self.register({**self.terms, field: value}).status_code == 409
        other_intent = {**self.terms, "intent_id": str(uuid.uuid4())}
        assert self.register(other_intent).status_code == 409
        assert EnvarDelegationRegistration.objects.count() == 1
        assert EnvarDelegationRegistration.objects.get().recipient == self.terms["recipient"]

    @override_settings(X402_ENVAR_DELEGATION_ENABLED=True, X402_ENVAR_DELEGATION_TOKEN="envar-secret")
    def test_rejects_non_base_excess_amount_expired_or_untrusted_fields(self):
        changes = [
            {"network": "eip155:84532"},
            {"amount_atomic": "10001"},
            {"amount_atomic": "0"},
            {"asset": "0x" + "4" * 40},
            {"recipient": "0xattacker"},
            {"expires_at": (timezone.now() - timedelta(minutes=1)).isoformat()},
            {"proof": "client-defined"},
            {"payee_revision": 0},
            {"terms_digest": "x" * 64},
        ]
        for change in changes:
            assert self.register({**self.terms, **change}).status_code == 400
        assert not EnvarDelegationRegistration.objects.exists()

    @override_settings(
        X402_ENVAR_DELEGATION_ENABLED=True,
        X402_ENVAR_DELEGATION_TOKEN="envar-secret",
        X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
        X402_SETTLE_TOKEN="internal-secret",
    )
    def test_normal_routes_still_refuse_registered_dynamic_recipient(self):
        assert self.register().status_code == 201
        body = _request_body()
        body["paymentRequirements"]["payTo"] = self.terms["recipient"]
        body["paymentPayload"]["accepted"]["payTo"] = self.terms["recipient"]
        verify = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        assert verify.status_code == 200 and verify.json()["isValid"] is False
        settle = self.client.post(
            reverse("x402:settle"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_X_SETTLEMENT_TOKEN="internal-secret",
        )
        assert settle.status_code == 200 and settle.json()["success"] is False
