"""Restricted upfront policy for Envar requests on standard x402 settlement."""

import hashlib
import re
import secrets
import uuid
from typing import Any

from django.conf import settings

BASE_NETWORK = "eip155:8453"
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PREFIX = "envar:"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
SIGNATURE = re.compile(r"0x[0-9a-fA-F]{130}\Z")
HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
AMOUNT = re.compile(r"[1-9][0-9]{0,4}\Z")


def authenticate(headers: Any) -> uuid.UUID:
    supplied = headers.get("X-Envar-Delegation-Token", "")
    expected = settings.X402_ENVAR_DELEGATION_TOKEN
    if (
        not settings.X402_ENVAR_DELEGATION_ENABLED
        or not expected
        or not supplied
        or secrets.compare_digest(expected, settings.X402_SETTLE_TOKEN)
        or not secrets.compare_digest(supplied, expected)
        or "X-Settlement-Token" in headers
        or settings.X402_BASE_NETWORK != BASE_NETWORK
        or settings.X402_BASE_CHAIN_ID != 8453
        or settings.X402_BASE_ASSET.lower() != BASE_USDC.lower()
        or not settings.X402_BASE_EXACT_ENABLED
    ):
        raise ValueError("Envar settlement is unavailable")
    raw = headers.get("X-Envar-Intent-Id", "")
    intent = uuid.UUID(raw)
    if not intent.int or str(intent) != raw:
        raise ValueError("Invalid intent")
    return intent


def validate_terms(data: Any, intent: uuid.UUID) -> None:
    if not isinstance(data, dict) or set(data) != {"x402Version", "paymentPayload", "paymentRequirements"}:
        raise ValueError("Invalid settle body")
    payload, terms = data["paymentPayload"], data["paymentRequirements"]
    if (
        type(data["x402Version"]) is not int
        or data["x402Version"] != 2
        or not isinstance(payload, dict)
        or set(payload) != {"x402Version", "accepted", "payload"}
        or type(payload["x402Version"]) is not int
        or payload["x402Version"] != 2
        or not isinstance(terms, dict)
        or set(terms) != {"scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"}
        or payload["accepted"] != terms
        or terms["scheme"] != "exact"
        or terms["network"] != BASE_NETWORK
        or not isinstance(terms["asset"], str)
        or terms["asset"].lower() != BASE_USDC.lower()
        or not isinstance(terms["amount"], str)
        or not AMOUNT.fullmatch(terms["amount"])
        or int(terms["amount"]) > 10_000
        or not isinstance(terms["payTo"], str)
        or not ADDRESS.fullmatch(terms["payTo"])
        or int(terms["payTo"], 16) == 0
        or type(terms["maxTimeoutSeconds"]) is not int
        or terms["maxTimeoutSeconds"] != 600
        or terms["extra"] != {"name": "USD Coin", "version": "2", "paymentFlow": "upfront"}
    ):
        raise ValueError("Unsupported Envar terms")
    signed = payload["payload"]
    if not isinstance(signed, dict) or set(signed) != {"signature", "authorization"}:
        raise ValueError("Expected EIP-3009")
    auth = signed["authorization"]
    if (
        not isinstance(signed["signature"], str)
        or not SIGNATURE.fullmatch(signed["signature"])
        or not isinstance(auth, dict)
        or set(auth) != {"from", "to", "value", "validAfter", "validBefore", "nonce"}
        or not isinstance(auth["from"], str)
        or not ADDRESS.fullmatch(auth["from"])
        or int(auth["from"], 16) == 0
        or auth["from"].lower() == terms["payTo"].lower()
        or not isinstance(auth["to"], str)
        or auth["to"].lower() != terms["payTo"].lower()
        or auth["value"] != terms["amount"]
        or auth["nonce"] != "0x" + hashlib.sha256(b"envar-delegation-payment-v1:" + intent.bytes).hexdigest()
        or any(
            not isinstance(auth[key], str) or not re.fullmatch(r"[0-9]{1,10}", auth[key])
            for key in ("validAfter", "validBefore")
        )
        or int(auth["validAfter"]) >= int(auth["validBefore"])
    ):
        raise ValueError("Authorization differs from frozen terms")


def is_envar(record: Any) -> bool:
    return str(record.verification_id or "").startswith(PREFIX)


def transfer_proven(record: Any, signer: Any) -> bool:
    terms = record.payment_requirements
    if (
        not is_envar(record)
        or not isinstance(record.transaction_hash, str)
        or not HASH.fullmatch(record.transaction_hash)
        or terms.get("network") != BASE_NETWORK
        or str(terms.get("asset", "")).lower() != BASE_USDC.lower()
        or terms.get("scheme") != "exact"
        or not AMOUNT.fullmatch(record.value)
        or not 0 < int(record.value) <= 10_000
        or terms.get("amount") != record.value
        or str(terms.get("payTo", "")).lower() != record.pay_to.lower()
    ):
        return False
    try:
        return (
            signer.has_exact_usdc_transfer(
                record.transaction_hash, BASE_USDC, record.payer, record.pay_to, int(record.value)
            )
            is True
        )
    except Exception:
        return False
