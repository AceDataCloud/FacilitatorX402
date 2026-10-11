import environs
import pytest

from core.x402_networks import load_evm_exact_networks

NETWORK_CASES = [
    ("arbitrum", 42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
]


@pytest.mark.parametrize("alias,chain_id,asset", NETWORK_CASES)
def test_new_rail_requires_explicit_enable_and_valid_recipient(monkeypatch, alias, chain_id, asset):
    prefix = f"X402_{alias.upper()}"
    monkeypatch.delenv(f"{prefix}_EXACT_ENABLED", raising=False)
    monkeypatch.setenv(f"{prefix}_PAY_TO", "0x" + "1" * 40)
    assert f"eip155:{chain_id}" not in load_evm_exact_networks(environs.Env())
    monkeypatch.setenv(f"{prefix}_EXACT_ENABLED", "true")
    config = load_evm_exact_networks(environs.Env())[f"eip155:{chain_id}"]
    assert config["asset"] == asset
    assert config["pay_to"] == "0x" + "1" * 40
    for invalid in ("", "0x" + "0" * 40, "0x" + "g" * 40, "solana-wallet"):
        monkeypatch.setenv(f"{prefix}_PAY_TO", invalid)
        with pytest.raises(ValueError, match="PAY_TO"):
            load_evm_exact_networks(environs.Env())


@pytest.mark.parametrize("alias,chain_id,asset", NETWORK_CASES)
def test_deployed_rail_receives_optional_secret_configuration(alias, chain_id, asset):
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for relative in ["deploy/production/deployment.yaml", "deploy/production/reconciliation-cronjob.yaml"]:
        source = (root / relative).read_text()
        for field in ["EXACT_ENABLED", "PAY_TO", "RPC_URL", "SIGNER_PRIVATE_KEY", "SIGNER_ADDRESS", "GAS_LIMIT"]:
            key = f"{alias.upper()}_{field}"
            pattern = (
                rf"(?m)^ +?- name: X402_{key}\n +valueFrom:\n +secretKeyRef:"
                rf"\n +name: x402\n +key: {key}\n +optional: true"
            )
            assert re.search(pattern, source), f"{relative} does not wire {key}"
