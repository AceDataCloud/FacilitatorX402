"""Tests for the verify-rejection diagnostics helper.

A production verify failure used to leave nothing behind: the HTTP response drops
`invalid_message`, and the payload is only persisted on the success path. Knowing
whether the payer is an EOA, a contract wallet, or an EIP-7702 delegation is the
first thing needed to triage a signature rejection, since the SDK routes accounts
with code through strict EIP-1271 with no ECDSA fallback.
"""

from unittest.mock import Mock, patch

from x402f.views_official import _payer_has_code

PAYER = "0x4e5c480271dc3a00a72062baae1ab6b40ef72c3f"
EVM_NETWORK = "eip155:8453"


def _patched(code: bytes | Exception):
    signer = Mock()
    if isinstance(code, Exception):
        signer.get_code.side_effect = code
    else:
        signer.get_code.return_value = code
    configured = Mock()
    configured.signer_for.return_value = signer
    return patch("x402f.views_official._configured", return_value=configured)


def test_reports_eoa_when_account_has_no_code() -> None:
    with _patched(b""):
        assert _payer_has_code(EVM_NETWORK, PAYER) == "eoa"


def test_reports_eip7702_delegation_by_prefix() -> None:
    # 0xef0100 || 20-byte delegate target
    with _patched(bytes.fromhex("ef0100") + b"\x11" * 20):
        assert _payer_has_code(EVM_NETWORK, PAYER) == "eip7702"


def test_reports_contract_with_code_size() -> None:
    with _patched(b"\x60\x80\x60\x40"):
        assert _payer_has_code(EVM_NETWORK, PAYER) == "contract(4b)"


def test_degrades_to_unknown_instead_of_raising() -> None:
    # Diagnostics must never turn a verify rejection into a 500.
    with _patched(RuntimeError("rpc down")):
        assert _payer_has_code(EVM_NETWORK, PAYER) == "unknown"


def test_skips_solana_and_empty_payers() -> None:
    assert _payer_has_code("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PAYER) == "n/a"
    assert _payer_has_code(EVM_NETWORK, "") == "n/a"
