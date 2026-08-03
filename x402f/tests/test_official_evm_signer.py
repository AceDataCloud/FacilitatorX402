"""Regression tests for EVM call-argument checksumming.

x402 2.16.0 checksums only the contract address, so a lowercase payer address in the
call arguments makes web3.py's ABI encoder raise InvalidAddress. Production saw that
surface as `invalid_exact_evm_transaction_simulation_failed`, which reads like an
on-chain rejection but is really a local encoding error.
"""

from unittest.mock import patch

import pytest
from web3 import Web3

from x402f.official_signer import DurableFacilitatorWeb3Signer, checksum_address_args

LOWERCASE_PAYER = "0x4e5c480271dc3a00a72062baae1ab6b40ef72c3f"
CHECKSUM_PAYER = Web3.to_checksum_address(LOWERCASE_PAYER)
BYTES32_NONCE = "0x" + "ab" * 32


def test_checksums_lowercase_address() -> None:
    assert checksum_address_args(LOWERCASE_PAYER) == CHECKSUM_PAYER


def test_checksums_addresses_nested_in_multicall_shape() -> None:
    # x402's multicall passes [(target, calldata), ...] straight through read_contract.
    assert checksum_address_args([(LOWERCASE_PAYER, b"\x01")]) == [(CHECKSUM_PAYER, b"\x01")]


@pytest.mark.parametrize(
    "value",
    [BYTES32_NONCE, "0x1234", b"\xde\xad", 12345, True, None, "not-an-address"],
)
def test_leaves_non_address_values_untouched(value: object) -> None:
    # A bytes32 nonce is also a hex string; mangling it would corrupt the EIP-3009 call.
    assert checksum_address_args(value) == value


def test_read_contract_checksums_arguments_before_encoding() -> None:
    signer = DurableFacilitatorWeb3Signer.__new__(DurableFacilitatorWeb3Signer)
    with patch(
        "x402.mechanisms.evm.signers.FacilitatorWeb3Signer.read_contract",
        return_value=0,
    ) as parent:
        signer.read_contract("0xabc", [], "authorizationState", LOWERCASE_PAYER, BYTES32_NONCE)

    assert parent.call_args.args == ("0xabc", [], "authorizationState", CHECKSUM_PAYER, BYTES32_NONCE)
