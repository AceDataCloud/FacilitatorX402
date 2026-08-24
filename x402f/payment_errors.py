from __future__ import annotations

from typing import Any

ERROR_SPECS: dict[str, tuple[str, bool]] = {
    "payer_token_account_missing": ("The payer's USDC token account is not ready for this payment.", True),
    "insufficient_token_balance": ("The wallet does not have enough USDC for this payment.", True),
    "authorization_expired": ("The payment authorization has expired.", True),
    "network_mismatch": ("The wallet is connected to a different network.", True),
    "invalid_signature": ("The payment signature is invalid.", True),
    "facilitator_unavailable": ("Payment verification is temporarily unavailable.", True),
    "settlement_pending": ("The payment result could not be confirmed yet.", False),
    "settlement_failed": ("The payment could not be settled.", False),
    "payment_failed": ("The payment could not be completed.", False),
}

REASON_TO_CODE = {
    "payer_token_account_missing": "payer_token_account_missing",
    "invalid_exact_evm_insufficient_balance": "insufficient_token_balance",
    "permit2_insufficient_balance": "insufficient_token_balance",
    "INSUFFICIENT_FUNDS": "insufficient_token_balance",
    "invalid_exact_evm_payload_authorization_valid_before": "authorization_expired",
    "invalid_exact_evm_authorization_expired": "authorization_expired",
    "permit2_deadline_expired": "authorization_expired",
    "network_mismatch": "network_mismatch",
    "invalid_exact_evm_payload_signature": "invalid_signature",
    "invalid_exact_svm_payload_signature": "invalid_signature",
    "invalid_permit2_signature": "invalid_signature",
    "invalid_payment_signature": "invalid_signature",
    "settlement_pending": "settlement_pending",
    "settlement_in_progress": "settlement_pending",
    "settlement_status_unavailable": "settlement_pending",
    "duplicate_settlement": "payment_failed",
}


def payment_error(
    reason: str | None,
    *,
    stage: str,
    network: str | None = None,
    asset: str | None = None,
    charged: bool | None = None,
) -> dict[str, Any]:
    code = REASON_TO_CODE.get(reason or "")
    if code is None:
        code = "settlement_failed" if stage == "settle" else "payment_failed"
    message, retryable = ERROR_SPECS[code]
    params = {}
    if network:
        params["network"] = str(network)[:128]
    if asset:
        params["asset"] = str(asset)[:128]
    descriptor: dict[str, Any] = {
        "code": code,
        "params": params,
        "stage": stage,
        "retryable": retryable,
        "message": message,
    }
    if charged is not None:
        descriptor["charged"] = charged
    return descriptor


def payment_error_extension(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {"acedatacloud": {"paymentError": descriptor}}
