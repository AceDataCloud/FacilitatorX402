import json
import os
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes

from x402.types import PaymentPayload, PaymentRequirements

from x402f.models import X402Authorization
from x402f.views import _build_typed_data


class X402FacilitatorViewTests(TestCase):
    def setUp(self) -> None:
        self.signer_account = Account.create('x402-facilitator-signer')
        self.payer_account = Account.create('x402-facilitator-payer')

        pay_to = self.signer_account.address
        usdc_contract = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

        overrides = override_settings(
            X402_RPC_URL='http://localhost:8545',
            X402_SIGNER_PRIVATE_KEY=self.signer_account.key.hex(),
            X402_SIGNER_ADDRESS=self.signer_account.address,
            X402_GAS_LIMIT=250000,
            X402_TX_TIMEOUT_SECONDS=10,
        )
        overrides.enable()
        self.addCleanup(overrides.disable)

        self.requirements = PaymentRequirements(
            scheme='exact',
            network='base',
            max_amount_required='1000000',
            resource='https://example.com/resource',
            description='Test order',
            mime_type='application/json',
            output_schema=None,
            pay_to=pay_to,
            max_timeout_seconds=600,
            asset=usdc_contract,
            extra={'name': 'USD Coin', 'version': '2'},
        )

    def _build_request_payload(self) -> dict:
        now = int(timezone.now().timestamp())
        nonce_hex = HexBytes(os.urandom(32)).hex()

        authorization = {
            'from': self.payer_account.address,
            'to': self.requirements.pay_to,
            'value': '250000',
            'validAfter': str(now - 60),
            'validBefore': str(now + 600),
            'nonce': nonce_hex,
        }

        payload_dict = {
            'x402Version': 1,
            'scheme': self.requirements.scheme,
            'network': str(self.requirements.network),
            'payload': {
                'signature': '0x' + '0' * 130,
                'authorization': authorization,
            },
        }

        payload_model = PaymentPayload.model_validate(payload_dict)
        typed_data = _build_typed_data(self.requirements, payload_model)
        signable = encode_typed_data(full_message=typed_data)
        signature = self.payer_account.sign_message(signable).signature.hex()
        payload_dict['payload']['signature'] = signature

        payload_model = PaymentPayload.model_validate(payload_dict)

        return {
            'paymentPayload': payload_model.model_dump(by_alias=True),
            'paymentRequirements': self.requirements.model_dump(by_alias=True),
        }

    def test_verify_persists_authorization(self):
        request_payload = self._build_request_payload()

        response = self.client.post(
            reverse('x402:verify'),
            data=json.dumps(request_payload),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['isValid'])
        self.assertEqual(X402Authorization.objects.count(), 1)
        record = X402Authorization.objects.first()
        self.assertEqual(record.status, X402Authorization.Status.VERIFIED)
        self.assertEqual(body['payer'], record.payer)

    def test_verify_rejects_replay(self):
        request_payload = self._build_request_payload()

        first = self.client.post(
            reverse('x402:verify'),
            data=json.dumps(request_payload),
            content_type='application/json',
        )
        self.assertEqual(first.status_code, 200)

        second = self.client.post(
            reverse('x402:verify'),
            data=json.dumps(request_payload),
            content_type='application/json',
        )

        body = second.json()
        self.assertFalse(body['isValid'])
        self.assertIn('nonce', body['invalidReason'])
        self.assertEqual(X402Authorization.objects.count(), 1)

    @patch('x402f.views._submit_transfer_with_authorization', return_value='0xabc123')
    def test_settle_marks_authorization_settled(self, submit_mock):
        request_payload = self._build_request_payload()

        verify_response = self.client.post(
            reverse('x402:verify'),
            data=json.dumps(request_payload),
            content_type='application/json',
        )
        self.assertEqual(verify_response.status_code, 200)

        settle_response = self.client.post(
            reverse('x402:settle'),
            data=json.dumps(request_payload),
            content_type='application/json',
        )

        self.assertEqual(settle_response.status_code, 200)
        body = settle_response.json()
        self.assertTrue(body['success'])
        self.assertEqual(body['transaction'], '0xabc123')

        record = X402Authorization.objects.get()
        self.assertEqual(record.status, X402Authorization.Status.SETTLED)
        self.assertEqual(record.transaction_hash, '0xabc123')
        submit_mock.assert_called_once()
