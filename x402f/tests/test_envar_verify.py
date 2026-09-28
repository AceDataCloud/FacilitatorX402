import json
import os
import time
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from x402.schemas import PaymentPayload, PaymentRequirements

from x402f.models import EnvarDelegationAuthorization, EnvarDelegationRegistration, X402Authorization
from x402f.official import build_facilitator
from x402f.tests.test_official_facilitator import USDC_BASE, FakeEvmSigner


@override_settings(
    X402_ENVAR_DELEGATION_ENABLED=True,
    X402_ENVAR_DELEGATION_TOKEN="envar-secret",
    X402_BASE_NETWORK="eip155:8453",
    X402_BASE_ASSET=USDC_BASE,
    X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
)
class EnvarVerifyTests(TestCase):
    def setUp(self):
        self.payer = Account.create()
        self.payee = Account.create()
        self.registration = EnvarDelegationRegistration.objects.create(
            intent_id=uuid.uuid4(),
            parent_run_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            request_owner_account_id="buyer",
            agent_id=uuid.uuid4(),
            owner_account_id="seller",
            agent_version_id=uuid.uuid4(),
            payee_revision=1,
            recipient=self.payee.address.lower(),
            network="eip155:8453",
            asset=USDC_BASE.lower(),
            amount_atomic="10000",
            terms_digest="a" * 64,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        self.signer = FakeEvmSigner()

    def payment(self, *, recipient=None, amount="10000", nonce=None):
        recipient = recipient or self.payee.address
        nonce = nonce or "0x" + os.urandom(32).hex()
        now = int(time.time())
        authorization = {
            "from": self.payer.address,
            "to": recipient,
            "value": amount,
            "validAfter": str(now - 60),
            "validBefore": str(now + 600),
            "nonce": nonce,
        }
        typed = {
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
            "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_BASE},
            "message": {
                **authorization,
                "value": int(amount),
                "validAfter": int(authorization["validAfter"]),
                "validBefore": int(authorization["validBefore"]),
                "nonce": HexBytes(nonce),
            },
        }
        signature = self.payer.sign_message(encode_typed_data(full_message=typed)).signature.hex()
        requirements = PaymentRequirements.model_validate(
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": USDC_BASE,
                "amount": amount,
                "payTo": recipient,
                "maxTimeoutSeconds": 600,
                "extra": {"name": "USD Coin", "version": "2"},
            }
        )
        payload = PaymentPayload.model_validate(
            {
                "x402Version": 2,
                "accepted": requirements.model_dump(by_alias=True),
                "payload": {"signature": signature, "authorization": authorization},
            }
        )
        return {
            "x402Version": 2,
            "paymentPayload": payload.model_dump(mode="json", by_alias=True),
            "paymentRequirements": requirements.model_dump(mode="json", by_alias=True),
        }

    def verify(self, payment, intent=None, token="envar-secret"):
        return self.client.post(
            reverse("x402:envar-delegation-verify"),
            data=json.dumps({"intent_id": str(intent or self.registration.intent_id), "payment": payment}),
            content_type="application/json",
            HTTP_X_ENVAR_DELEGATION_TOKEN=token,
        )

    def test_signed_exact_authorization_binds_once_without_broadcast(self):
        payment = self.payment()
        with patch("x402f.delegation_verify._configured") as configured:
            configured.return_value.facilitator = build_facilitator(self.signer)
            first = self.verify(payment)
            replay = self.verify(payment)
        assert first.status_code == 200 and first.json()["isValid"] is True, first.content
        assert replay.json()["isValid"] is True
        assert self.signer.simulated_transfer is True
        assert EnvarDelegationAuthorization.objects.count() == 1
        assert X402Authorization.objects.count() == 1
        assert X402Authorization.objects.get().status == X402Authorization.Status.VERIFIED
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
            asset=USDC_BASE.lower(),
            amount_atomic="10000",
            terms_digest="a" * 64,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        assert self.verify(payment, other.intent_id).json()["isValid"] is False

    def test_wrong_recipient_amount_and_token_do_not_reserve(self):
        wrong_recipient = self.payment(recipient=Account.create().address)
        wrong_amount = self.payment(amount="9999")
        assert self.verify(wrong_recipient).json()["isValid"] is False
        assert self.verify(wrong_amount).json()["isValid"] is False
        assert self.verify(self.payment(), token="wrong").status_code == 403
        assert not X402Authorization.objects.exists()

    def test_normal_verify_does_not_accept_registered_recipient(self):
        body = self.payment()
        ordinary = self.client.post(reverse("x402:verify"), data=json.dumps(body), content_type="application/json")
        assert ordinary.json()["isValid"] is False

    def test_expired_registration_cannot_reserve(self):
        EnvarDelegationRegistration.objects.filter(pk=self.registration.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        assert self.verify(self.payment()).json()["isValid"] is False
        assert not X402Authorization.objects.exists()
