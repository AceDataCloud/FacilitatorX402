from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from core.exact_recipients import BASE, SOLANA, load_additional_exact_recipients
from x402f.views_official import _validate_policy

BASE_EXTRA = "0xdd457Ac1Bb07e93E1D360368B66d7316FC010647"
SOL_EXTRA = "ECc8ficTwNNYHNxepdNrVC9tyg3iH46Xv9eiKrqUR9q4"
BASE_PRIMARY = "0x1111111111111111111111111111111111111111"
SOL_PRIMARY = "AdK3dtj4iV4QNepwPQRGBeJW3WUFXUXhnBiGFkGuBAzC"
BASE_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SOL_ASSET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def request(network: str, recipient: str, scheme: str = "exact", asset: str | None = None):
    return SimpleNamespace(
        payment_requirements=SimpleNamespace(
            network=network,
            pay_to=recipient,
            scheme=scheme,
            asset=asset or (BASE_ASSET if network == BASE else SOL_ASSET),
        ),
        payment_payload={"payload": {}},
    )


@pytest.fixture(autouse=True)
def configured():
    with override_settings(
        X402_BASE_NETWORK=BASE,
        X402_BASE_EXACT_ENABLED=True,
        X402_BASE_UPTO_ENABLED=True,
        X402_BASE_ASSET=BASE_ASSET,
        X402_BASE_PAY_TO=BASE_PRIMARY,
        X402_SOLANA_MAINNET_ENABLED=True,
        X402_SOLANA_ASSET=SOL_ASSET,
        X402_SOLANA_PAY_TO=SOL_PRIMARY,
        X402_ADDITIONAL_EXACT_RECIPIENTS=load_additional_exact_recipients({BASE: [BASE_EXTRA], SOLANA: [SOL_EXTRA]}),
    ):
        yield


@pytest.mark.parametrize("network,primary,extra", [(BASE, BASE_PRIMARY, BASE_EXTRA), (SOLANA, SOL_PRIMARY, SOL_EXTRA)])
def test_only_explicit_exact_recipients_are_added(network, primary, extra):
    _validate_policy(request(network, primary))
    _validate_policy(request(network, extra))
    with override_settings(X402_ADDITIONAL_EXACT_RECIPIENTS={}):
        with pytest.raises(ValueError, match="recipient"):
            _validate_policy(request(network, extra))


def test_upto_keeps_original_recipient_boundary():
    _validate_policy(request(BASE, BASE_PRIMARY, "upto"))
    with pytest.raises(ValueError, match="recipient"):
        _validate_policy(request(BASE, BASE_EXTRA, "upto"))


def test_extra_recipient_does_not_enable_rail_or_replace_primary_or_asset():
    with override_settings(X402_BASE_EXACT_ENABLED=False):
        with pytest.raises(ValueError, match="kind"):
            _validate_policy(request(BASE, BASE_EXTRA))
    with override_settings(X402_BASE_PAY_TO=""):
        with pytest.raises(ValueError, match="recipient"):
            _validate_policy(request(BASE, BASE_EXTRA))
    with pytest.raises(ValueError, match="asset"):
        _validate_policy(request(BASE, BASE_EXTRA, asset=BASE_PRIMARY))


def test_base_case_normalization_and_solana_case_sensitivity():
    _validate_policy(request(BASE, BASE_EXTRA.lower()))
    with pytest.raises(ValueError, match="recipient"):
        _validate_policy(request(SOLANA, SOL_EXTRA.lower()))


@pytest.mark.parametrize(
    "value",
    [
        [],
        {BASE: BASE_EXTRA},
        {BASE: ["0x" + "0" * 40]},
        {BASE: [None]},
        {SOLANA: ["bad"]},
        {"eip155:84532": [BASE_EXTRA]},
    ],
)
def test_invalid_additional_recipients_fail_closed(value):
    with pytest.raises(ImproperlyConfigured):
        load_additional_exact_recipients(value)
