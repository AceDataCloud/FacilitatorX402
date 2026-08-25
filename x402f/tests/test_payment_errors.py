from x402f.payment_errors import payment_error


def test_reason_mapping_is_centralized() -> None:
    assert payment_error("invalid_exact_evm_insufficient_balance", stage="verify", charged=False) == {
        "code": "insufficient_token_balance",
        "params": {},
        "stage": "verify",
        "retryable": True,
        "message": "The wallet does not have enough USDC for this payment.",
        "charged": False,
    }


def test_settlement_uncertainty_never_claims_not_charged() -> None:
    error = payment_error("settlement_status_unavailable", stage="settle", network="eip155:8453")
    assert error["code"] == "settlement_pending"
    assert error["retryable"] is True
    assert "charged" not in error


def test_unknown_reasons_fail_closed() -> None:
    assert payment_error("future_reason", stage="verify")["code"] == "payment_failed"
    assert payment_error("future_reason", stage="settle")["code"] == "settlement_failed"
