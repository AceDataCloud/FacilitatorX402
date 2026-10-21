from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from hexbytes import HexBytes
from web3 import Web3

from x402f.official_signer import DurableFacilitatorWeb3Signer


def receipt(asset, payer, recipient, amount, tx_hash, *, duplicate=False):
    log = {
        "address": asset,
        "topics": [
            Web3.keccak(text="Transfer(address,address,uint256)"),
            HexBytes(payer).rjust(32, b"\x00"),
            HexBytes(recipient).rjust(32, b"\x00"),
        ],
        "data": amount.to_bytes(32, "big"),
    }
    return {"status": 1, "transactionHash": HexBytes(tx_hash), "logs": [log, log] if duplicate else [log]}


def test_base_usdc_receipt_matches_one_exact_transfer():
    asset = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    payer = "0x" + "1" * 40
    recipient = "0x" + "2" * 40
    tx_hash = "0x" + "a" * 64
    signer = DurableFacilitatorWeb3Signer.__new__(DurableFacilitatorWeb3Signer)
    signer._w3 = SimpleNamespace(eth=SimpleNamespace(get_transaction_receipt=Mock()))
    signer._w3.eth.get_transaction_receipt.return_value = receipt(asset, payer, recipient, 10000, tx_hash)
    assert signer.has_exact_usdc_transfer(tx_hash, asset, payer, recipient, 10000)
    assert not signer.has_exact_usdc_transfer(tx_hash, asset, payer, recipient, 9999)
    assert not signer.has_exact_usdc_transfer(tx_hash, asset, recipient, payer, 10000)
    assert not signer.has_exact_usdc_transfer(tx_hash, "0x" + "3" * 40, payer, recipient, 10000)
    signer._w3.eth.get_transaction_receipt.return_value = receipt(
        asset, payer, recipient, 10000, tx_hash, duplicate=True
    )
    assert not signer.has_exact_usdc_transfer(tx_hash, asset, payer, recipient, 10000)


@pytest.mark.parametrize("mutation", ["failed", "wrong_hash", "missing", "removed", "short_data"])
def test_incomplete_or_invalid_receipts_do_not_prove_transfer(mutation):
    asset = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    payer, recipient, tx_hash = "0x" + "1" * 40, "0x" + "2" * 40, "0x" + "a" * 64
    value = receipt(asset, payer, recipient, 10000, tx_hash)
    if mutation == "failed":
        value["status"] = 0
    elif mutation == "wrong_hash":
        value["transactionHash"] = HexBytes("0x" + "b" * 64)
    elif mutation == "missing":
        value["logs"] = []
    elif mutation == "removed":
        value["logs"][0]["removed"] = True
    else:
        value["logs"][0]["data"] = (10000).to_bytes(2, "big")
    signer = DurableFacilitatorWeb3Signer.__new__(DurableFacilitatorWeb3Signer)
    signer._w3 = SimpleNamespace(eth=SimpleNamespace(get_transaction_receipt=Mock(return_value=value)))
    assert not signer.has_exact_usdc_transfer(tx_hash, asset, payer, recipient, 10000)
