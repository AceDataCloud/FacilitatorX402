from unittest.mock import patch

import environs
import pytest
from django.test import override_settings
from x402.schemas import PaymentPayload, PaymentRequirements, VerifyRequest

from core.x402_networks import load_evm_exact_networks
from x402f.official import build_configured_registry, configured_supported_response
from x402f.tests.test_official_facilitator import FakeEvmSigner
from x402f.views_official import _validate_policy

NETWORK_CASES = [
    ("arbitrum", 42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
]


@pytest.mark.parametrize("alias,chain_id,asset", NETWORK_CASES)
def test_new_network_routes_only_exact_to_its_own_signer(monkeypatch, alias, chain_id, asset):
    monkeypatch.setenv(f"X402_{alias.upper()}_EXACT_ENABLED", "true")
    monkeypatch.setenv(f"X402_{alias.upper()}_PAY_TO", "0x" + "1" * 40)
    networks = load_evm_exact_networks(environs.Env())
    network = f"eip155:{chain_id}"
    config = networks[network]
    signer = FakeEvmSigner()
    config.update(
        rpc_url="https://rpc.invalid", private_key="test-only", address=signer.account.address, gas_limit=500000
    )
    with override_settings(X402_EVM_EXACT_NETWORKS=networks):
        with patch("x402f.official._evm_signer", return_value=signer) as builder:
            registry = build_configured_registry(networks={network})
        assert registry.signer_for(network) is signer
        assert builder.call_args.kwargs["chain_id"] == chain_id
        assert builder.call_args.kwargs["rpc_url"] == "https://rpc.invalid"
        kinds = registry.facilitator.get_supported().kinds
        assert [(kind.scheme, kind.network) for kind in kinds] == [("exact", network)]
        with override_settings(X402_BASE_EXACT_ENABLED=False, X402_BASE_UPTO_ENABLED=False):
            advertised = configured_supported_response()
        assert any(kind.network == network and kind.scheme == "exact" for kind in advertised.kinds)

        requirements = PaymentRequirements(
            scheme="exact",
            network=network,
            asset=asset,
            amount="10000",
            pay_to=config["pay_to"],
            max_timeout_seconds=60,
        )

        def request(req):
            return VerifyRequest(
                x402_version=2,
                payment_requirements=req,
                payment_payload=PaymentPayload(x402_version=2, accepted=req, payload={}),
            )

        _validate_policy(request(requirements))
        for field, value, reason in (
            ("asset", "0x" + "2" * 40, "asset"),
            ("pay_to", "0x" + "2" * 40, "recipient"),
            ("scheme", "upto", "kind"),
        ):
            with pytest.raises(ValueError, match=reason):
                _validate_policy(request(requirements.model_copy(update={field: value})))
    with override_settings(X402_EVM_EXACT_NETWORKS={}):
        with pytest.raises(ValueError, match="network"):
            _validate_policy(request(requirements))
