import environs
import pytest

from core.x402_networks import load_evm_exact_networks

NETWORK_CASES = [
    ("arbitrum", 42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    ("polygon", 137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
]


@pytest.mark.parametrize("alias,chain_id,asset", NETWORK_CASES)
def test_new_rail_requires_explicit_enable_independent_of_recipient_policy(monkeypatch, alias, chain_id, asset):
    prefix = f"X402_{alias.upper()}"
    monkeypatch.delenv(f"{prefix}_EXACT_ENABLED", raising=False)
    assert f"eip155:{chain_id}" not in load_evm_exact_networks(environs.Env())
    monkeypatch.setenv(f"{prefix}_EXACT_ENABLED", "true")
    config = load_evm_exact_networks(environs.Env())[f"eip155:{chain_id}"]
    assert config["asset"] == asset
    assert "pay_to" not in config


@pytest.mark.parametrize("alias,chain_id,asset", NETWORK_CASES)
def test_deployed_rail_receives_optional_secret_configuration(alias, chain_id, asset):
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for relative in ["deploy/production/deployment.yaml", "deploy/production/reconciliation-cronjob.yaml"]:
        source = (root / relative).read_text()
        enabled = source.split(f"- name: X402_{alias.upper()}_EXACT_ENABLED", 1)[1].split("- name:", 1)[0]
        assert 'value: "false"' in enabled
        assert f"X402_{alias.upper()}_SIGNER_PRIVATE_KEY" not in source
        for field in ["RPC_URL", "SIGNER_ADDRESS", "GAS_LIMIT"]:
            key = f"{alias.upper()}_{field}"
            secret_name = "x402"
            pattern = (
                rf"(?m)^ +?- name: X402_{key}\n +valueFrom:\n +secretKeyRef:"
                rf"\n +name: {secret_name}\n +key: {key}\n +optional: true"
            )
            assert re.search(pattern, source), f"{relative} does not wire {key}"
