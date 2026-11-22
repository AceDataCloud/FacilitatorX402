import copy
from types import SimpleNamespace

import pytest
from django.test import override_settings
from eth_account import Account
from x402.schemas import PaymentPayload, PaymentRequirements

from x402f.official import build_facilitator
from x402f.tests.test_official_facilitator import USDC_BASE, FakeEvmSigner, _payment
from x402f.tests.test_official_views import _request_body, _upto_request_body
from x402f.views_official import _validate_policy


def request(network, scheme, asset, pay_to):
    return SimpleNamespace(
        payment_requirements=SimpleNamespace(network=network, scheme=scheme, asset=asset, pay_to=pay_to),
        payment_payload={"payload": {}},
    )


@pytest.mark.parametrize("scheme", ["exact", "upto"])
def test_base_policy_does_not_require_merchant_registration(scheme):
    with override_settings(X402_BASE_EXACT_ENABLED=True, X402_BASE_UPTO_ENABLED=True):
        for _ in range(3):
            _validate_policy(request("eip155:8453", scheme, USDC_BASE, Account.create().address))


def test_network_asset_and_scheme_gates_remain():
    recipient = Account.create().address
    with override_settings(X402_BASE_EXACT_ENABLED=True, X402_BASE_UPTO_ENABLED=False):
        _validate_policy(request("eip155:8453", "exact", USDC_BASE, recipient))
        with pytest.raises(ValueError, match="asset"):
            _validate_policy(request("eip155:8453", "exact", recipient, recipient))
        with pytest.raises(ValueError, match="kind"):
            _validate_policy(request("eip155:8453", "upto", USDC_BASE, recipient))
        with pytest.raises(ValueError, match="network"):
            _validate_policy(request("eip155:999999", "exact", USDC_BASE, recipient))


def test_sdk_verifies_real_signatures_for_arbitrary_evm_recipients():
    for _ in range(3):
        signer = FakeEvmSigner()
        facilitator = build_facilitator(signer)
        payload, requirements = _payment()
        assert facilitator.verify(payload, requirements).is_valid
        assert signer.simulated_transfer


def test_client_cannot_use_a_self_selected_recipient_against_business_requirements():
    payload, signed_requirements = _payment(pay_to_self=True)
    assert build_facilitator(FakeEvmSigner()).verify(payload, signed_requirements).is_valid
    # Gateway supplies its own requirements even if the client chooses different
    # accepted terms. The signed recipient must satisfy the business's payTo.
    business_requirements = signed_requirements.model_copy(update={"pay_to": Account.create().address})
    result = build_facilitator(FakeEvmSigner()).verify(payload, business_requirements)
    assert not result.is_valid


def test_changed_recipient_requires_a_new_payer_signature():
    payload, requirements = _payment()
    other = Account.create().address
    changed = requirements.model_copy(update={"pay_to": other})
    body = copy.deepcopy(payload.model_dump(mode="json", by_alias=True))
    body["accepted"] = changed.model_dump(mode="json", by_alias=True)
    body["payload"]["authorization"]["to"] = other
    forged = PaymentPayload.model_validate(body)
    assert not build_facilitator(FakeEvmSigner()).verify(forged, changed).is_valid


def test_permit2_witness_must_match_the_business_recipient():
    body = _upto_request_body(_request_body())
    payload = PaymentPayload.model_validate(body["paymentPayload"])
    business = PaymentRequirements.model_validate(body["paymentRequirements"]).model_copy(
        update={"pay_to": Account.create().address}
    )
    result = build_facilitator(FakeEvmSigner(), enable_upto=True).verify(payload, business)
    assert not result.is_valid
    assert "recipient" in result.invalid_reason
