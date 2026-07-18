"""Unit tests for the x402 `upto` scheme handler.

These are pure-Python tests: no Django ORM, no live RPC. They cover:
- Factory dispatch keyed by (network, scheme)
- Typed-data structure matches the spec exactly
- Payload parser tolerates legacy and current field naming
- Verifier rejects mismatches without touching the network
"""

from __future__ import annotations

import time
from typing import Any, Dict

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from x402f.chain_handlers import (
    BaseUptoHandler,
    ChainHandlerFactory,
    SkaleUptoHandler,
)
from x402f.chain_handlers.base_upto import (
    ERR_AMOUNT_MISMATCH,
    ERR_FACILITATOR_MISMATCH,
    ERR_INVALID_SIGNATURE,
    ERR_INVALID_SPENDER,
    ERR_NOT_YET_VALID,
    ERR_RECIPIENT_MISMATCH,
    ERR_TOKEN_MISMATCH,
    _parse_upto_payload,
    _split_settle_revert,
)
from x402f.chain_handlers.upto_constants import (
    PERMIT2_ADDRESS,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
    build_upto_permit2_typed_data,
)

CHAIN_ID = 8453  # Base mainnet
SKALE_CHAIN_ID = 1187947933
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PAY_TO = "0x0000000000000000000000000000000000000123"
FACILITATOR_EOA = None  # filled per-test from the signer account

# Deterministic test wallet (not used on-chain)
TEST_PRIVATE_KEY = "0x" + "11" * 32


def test_custom_payment_too_early_selector_is_actionable():
    assert _split_settle_revert(Exception("execution reverted: 0xa65539fa")) == ERR_NOT_YET_VALID


def _make_signer():
    return Account.from_key(TEST_PRIVATE_KEY)


def _sign_upto(*, amount: int, deadline: int, valid_after: int, nonce: int, facilitator: str) -> Dict[str, Any]:
    """Build a signed upto envelope identical to what X402Client would produce."""
    signer = _make_signer()
    typed = build_upto_permit2_typed_data(
        chain_id=CHAIN_ID,
        permitted_token=USDC,
        permitted_amount=amount,
        nonce=nonce,
        deadline=deadline,
        witness_to=PAY_TO,
        witness_facilitator=facilitator,
        witness_valid_after=valid_after,
    )
    signable = encode_typed_data(full_message=typed)
    sig = signer.sign_message(signable).signature
    return {
        "x402Version": 2,
        "scheme": "upto",
        "network": "base",
        "payload": {
            "signature": "0x" + sig.hex() if not sig.hex().startswith("0x") else sig.hex(),
            "permit2Authorization": {
                "permitted": {"token": USDC, "amount": str(amount)},
                "from": signer.address,
                "spender": X402_UPTO_PERMIT2_PROXY_ADDRESS,
                "nonce": str(nonce),
                "deadline": str(deadline),
                "witness": {
                    "to": PAY_TO,
                    "facilitator": facilitator,
                    "validAfter": str(valid_after),
                },
            },
        },
    }


def _requirements(amount: int, facilitator: str) -> Dict[str, Any]:
    return {
        "scheme": "upto",
        "network": "base",
        "payTo": PAY_TO,
        "asset": USDC,
        "amount": str(amount),
        "extra": {"facilitatorAddress": facilitator},
    }


def _handler(facilitator: str) -> BaseUptoHandler:
    # rpc_url left empty so on-chain preflight + simulate fail open.
    return BaseUptoHandler(
        config={
            "chain_name": "base",
            "chain_id": CHAIN_ID,
            "signer_address": facilitator,
        }
    )


def test_factory_dispatches_base_upto():
    h = ChainHandlerFactory.create("base", {"chain_id": CHAIN_ID}, scheme="upto")
    assert isinstance(h, BaseUptoHandler)


def test_factory_dispatches_skale_upto():
    h = ChainHandlerFactory.create("skale", {"chain_id": SKALE_CHAIN_ID}, scheme="upto")
    assert isinstance(h, SkaleUptoHandler)
    # SkaleUptoHandler is a thin subclass of BaseUptoHandler
    assert isinstance(h, BaseUptoHandler)


def test_skale_upto_uses_gateway_chain_id_by_default(monkeypatch):
    import django

    monkeypatch.delenv("X402_SKALE_CHAIN_ID", raising=False)
    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "core.settings")
    django.setup()

    from x402f.views_multichain import _get_chain_config

    assert _get_chain_config("skale")["chain_id"] == SKALE_CHAIN_ID
    assert _get_chain_config("skale")["gas_limit"] == 400000


def test_skale_upto_ignores_unreliable_rpc_gas_estimate():
    handler = SkaleUptoHandler({"chain_id": SKALE_CHAIN_ID, "gas_limit": 400000})

    assert handler._transaction_gas_limit(50000000) == 400000


def test_supported_upto_entries_include_chain_id(monkeypatch):
    import django

    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "core.settings")
    django.setup()

    from django.conf import settings

    from x402f.views_multichain import X402SupportedView

    settings.X402_BASE_SIGNER_ADDRESS = _make_signer().address
    settings.X402_SKALE_SIGNER_ADDRESS = _make_signer().address
    settings.X402_BASE_CHAIN_ID = CHAIN_ID
    settings.X402_SKALE_CHAIN_ID = SKALE_CHAIN_ID

    response = X402SupportedView().get(None)
    kinds = response.data["kinds"]

    base_upto = next(item for item in kinds if item["network"] == "base" and item["scheme"] == "upto")
    skale_upto = next(item for item in kinds if item["network"] == "skale" and item["scheme"] == "upto")
    assert base_upto["extra"]["chainId"] == CHAIN_ID
    assert skale_upto["extra"]["chainId"] == SKALE_CHAIN_ID


def test_factory_unsupported_scheme_raises():
    with pytest.raises(ValueError, match="Unsupported"):
        ChainHandlerFactory.create("solana", {}, scheme="upto")


def test_typed_data_uses_canonical_permit2_domain():
    td = build_upto_permit2_typed_data(
        chain_id=8453,
        permitted_token=USDC,
        permitted_amount=100,
        nonce=1,
        deadline=2,
        witness_to=PAY_TO,
        witness_facilitator=PAY_TO,
        witness_valid_after=0,
    )
    assert td["domain"]["verifyingContract"] == PERMIT2_ADDRESS
    assert td["domain"]["name"] == "Permit2"
    assert "version" not in td["domain"]
    assert td["primaryType"] == "PermitWitnessTransferFrom"
    assert td["message"]["spender"] == X402_UPTO_PERMIT2_PROXY_ADDRESS


def test_parse_payload_extracts_all_fields():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=42, facilitator=facilitator)
    parsed, err = _parse_upto_payload(env)
    assert err is None
    assert parsed["from_address"].lower() == _make_signer().address.lower()
    assert parsed["permitted_amount"] == 100
    assert parsed["nonce"] == 42
    assert parsed["witness_to"] == PAY_TO


def test_parse_payload_missing_witness_returns_invalid():
    env = {
        "payload": {
            "signature": "0xdeadbeef",
            "permit2Authorization": {
                "permitted": {"token": USDC, "amount": "100"},
                "from": "0xabc",
                "spender": X402_UPTO_PERMIT2_PROXY_ADDRESS,
                "nonce": "1",
                "deadline": "999",
                "witness": {},
            },
        },
    }
    _, err = _parse_upto_payload(env)
    assert err is not None


def test_verify_accepts_well_formed_signature_when_rpc_unavailable():
    facilitator = _make_signer().address
    env = _sign_upto(
        amount=100,
        deadline=int(time.time()) + 600,
        valid_after=int(time.time()) - 10,
        nonce=1,
        facilitator=facilitator,
    )
    handler = _handler(facilitator)
    result = handler.verify_signature(env, _requirements(100, facilitator))
    # preflight + simulate fail-open because rpc_url is "" — verify still passes
    assert result.is_valid, result.invalid_reason
    assert result.payer.lower() == _make_signer().address.lower()
    assert result.details["amount"] == 100
    assert result.details["permitted_amount"] == 100


def test_verify_rejects_recipient_mismatch():
    facilitator = _make_signer().address
    env = _sign_upto(
        amount=100,
        deadline=int(time.time()) + 600,
        valid_after=0,
        nonce=2,
        facilitator=facilitator,
    )
    reqs = _requirements(100, facilitator)
    reqs["payTo"] = "0x0000000000000000000000000000000000000999"
    result = _handler(facilitator).verify_signature(env, reqs)
    assert not result.is_valid
    assert result.invalid_reason == ERR_RECIPIENT_MISMATCH


def test_verify_rejects_token_mismatch():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=3, facilitator=facilitator)
    reqs = _requirements(100, facilitator)
    reqs["asset"] = "0x0000000000000000000000000000000000000abc"
    result = _handler(facilitator).verify_signature(env, reqs)
    assert not result.is_valid
    assert result.invalid_reason == ERR_TOKEN_MISMATCH


def test_verify_rejects_facilitator_mismatch():
    real_facilitator = _make_signer().address
    fake_facilitator = "0x000000000000000000000000000000000000dead"
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=4, facilitator=fake_facilitator)
    result = _handler(real_facilitator).verify_signature(env, _requirements(100, real_facilitator))
    assert not result.is_valid
    assert result.invalid_reason == ERR_FACILITATOR_MISMATCH


def test_verify_rejects_amount_mismatch():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=5, facilitator=facilitator)
    result = _handler(facilitator).verify_signature(env, _requirements(200, facilitator))
    assert not result.is_valid
    assert result.invalid_reason == ERR_AMOUNT_MISMATCH


def test_verify_rejects_spender_tampering():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=6, facilitator=facilitator)
    env["payload"]["permit2Authorization"]["spender"] = "0x0000000000000000000000000000000000000bad"
    result = _handler(facilitator).verify_signature(env, _requirements(100, facilitator))
    assert not result.is_valid
    assert result.invalid_reason == ERR_INVALID_SPENDER


def test_verify_rejects_tampered_signature():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=7, facilitator=facilitator)
    typed = build_upto_permit2_typed_data(
        chain_id=CHAIN_ID,
        permitted_token=USDC,
        permitted_amount=100,
        nonce=7,
        deadline=int(env["payload"]["permit2Authorization"]["deadline"]),
        witness_to=PAY_TO,
        witness_facilitator=facilitator,
        witness_valid_after=0,
    )
    other = Account.from_key("0x" + "22" * 32)
    signature = other.sign_message(encode_typed_data(full_message=typed)).signature.hex()
    env["payload"]["signature"] = "0x" + signature.removeprefix("0x")
    result = _handler(facilitator).verify_signature(env, _requirements(100, facilitator))
    assert not result.is_valid
    assert result.invalid_reason == ERR_INVALID_SIGNATURE


def test_settle_zero_amount_skips_onchain():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=8, facilitator=facilitator)
    reqs = _requirements(0, facilitator)  # actual = 0
    result = _handler(facilitator).settle_payment(env, reqs)
    assert result.success
    assert result.transaction_hash == ""
    assert result.details["amount"] == 0
    assert result.details["skipped"] is True


def test_settle_rejects_amount_exceeding_permitted():
    facilitator = _make_signer().address
    env = _sign_upto(amount=100, deadline=int(time.time()) + 600, valid_after=0, nonce=9, facilitator=facilitator)
    reqs = _requirements(200, facilitator)  # exceeds permit ceiling
    result = _handler(facilitator).settle_payment(env, reqs)
    assert not result.success
    assert "settlement_exceeds_amount" in result.error_reason
