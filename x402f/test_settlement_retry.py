"""
Test suite for X402 settlement retry logic.

These tests verify:
1. Transient errors are correctly classified as retryable
2. Non-retryable errors fail immediately without retries
3. Backoff delays are calculated correctly
4. Retry attempts are tracked accurately
5. Various error types are handled appropriately
"""

import pytest
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from x402f.settlement_enhancements import (
    RetryConfig,
    SettlementAttempts,
    SettlementError,
    SettlementErrorType,
    classify_error,
    should_log_as_error,
)


class TestErrorClassification:
    """Test that errors are classified correctly."""

    def test_balance_insufficient_is_retryable(self):
        """Balance insufficient errors should be classified as retryable."""
        exc = ContractLogicError("amount exceeds balance")
        error = classify_error(exc)

        assert error.error_type == SettlementErrorType.BALANCE_INSUFFICIENT
        assert error.is_retryable
        assert error.is_preflight_only
        assert error.should_skip_preflight_on_retry

    def test_insufficient_funds_is_configuration_error(self):
        """Insufficient gas funds should be non-retryable configuration error."""
        exc = ContractLogicError("insufficient funds")
        error = classify_error(exc)

        assert error.error_type == SettlementErrorType.SIGNER_MISCONFIGURED
        assert not error.is_retryable

    def test_rpc_unavailable_is_retryable(self):
        """RPC connection errors should be retryable."""
        exc = ConnectionError("Unable to connect to RPC")
        error = classify_error(exc)

        assert error.error_type == SettlementErrorType.RPC_UNAVAILABLE
        assert error.is_retryable
        assert not error.is_preflight_only

    def test_bad_function_call_output_is_mixed_error(self):
        """BadFunctionCallOutput indicates possible non-standard contract."""
        exc = BadFunctionCallOutput("")
        error = classify_error(exc)

        assert error.error_type == SettlementErrorType.CONTRACT_REVERTED
        assert error.is_retryable  # Could be transient


class TestRetryConfig:
    """Test retry configuration and delay calculation."""

    def test_default_config_values(self):
        """Default retry config has sensible values."""
        config = RetryConfig()

        assert config.max_retries_preflight == 3
        assert config.max_retries_balance == 5
        assert config.initial_delay_ms == 100
        assert config.max_delay_ms == 5000
        assert config.backoff_factor == 2.0

    def test_get_max_retries_with_override(self):
        """Error-specific max retries should override defaults."""
        config = RetryConfig()

        balance_retries = config.get_max_retries(SettlementErrorType.BALANCE_INSUFFICIENT)
        assert balance_retries == 5  # Custom value in error_max_retries

        generic_retries = config.get_max_retries(SettlementErrorType.UNKNOWN)
        assert generic_retries == 3  # Falls back to max_retries_preflight

    def test_delay_calculation_exponential(self):
        """Delays should increase exponentially."""
        config = RetryConfig()

        delay_0 = config.get_delay_ms(0)  # First retry
        delay_1 = config.get_delay_ms(1)  # Second retry
        delay_2 = config.get_delay_ms(2)  # Third retry

        # 100ms, 200ms, 400ms
        assert delay_0 == 100
        assert delay_1 == 200
        assert delay_2 == 400

    def test_delay_capped_at_max(self):
        """Delays should not exceed max."""
        config = RetryConfig(initial_delay_ms=2000, max_delay_ms=5000)

        # 2000 * 2^0 = 2000
        # 2000 * 2^1 = 4000
        # 2000 * 2^2 = 8000 -> capped at 5000
        # 2000 * 2^3 = 16000 -> capped at 5000

        assert config.get_delay_ms(0) == 2000
        assert config.get_delay_ms(1) == 4000
        assert config.get_delay_ms(2) == 5000  # Capped
        assert config.get_delay_ms(3) == 5000  # Still capped


class TestSettlementAttempts:
    """Test attempts tracking and retry decision logic."""

    def test_add_attempt_success(self):
        """Track successful attempt."""
        attempts = SettlementAttempts(nonce="test-nonce")

        attempt = attempts.add_attempt(error=None, tx_hash="0x123")

        assert attempt.attempt_num == 1
        assert attempt.succeeded
        assert attempt.tx_hash == "0x123"

    def test_add_attempt_failure(self):
        """Track failed attempt."""
        attempts = SettlementAttempts(nonce="test-nonce")
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test error")

        attempt = attempts.add_attempt(error=error, tx_hash=None)

        assert attempt.attempt_num == 1
        assert attempt.failed
        assert attempt.error == error

    def test_can_retry_retryable_error(self):
        """Should be able to retry retryable errors."""
        attempts = SettlementAttempts(nonce="test-nonce", config=RetryConfig(max_retries_preflight=3))
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        attempts.add_attempt(error=error, tx_hash=None)

        can_retry, reason = attempts.can_retry()
        assert can_retry
        assert reason is None

    def test_can_retry_non_retryable_error(self):
        """Should not retry non-retryable errors."""
        attempts = SettlementAttempts(nonce="test-nonce")
        error = SettlementError(SettlementErrorType.INVALID_SIGNATURE, "test")

        attempts.add_attempt(error=error, tx_hash=None)

        can_retry, reason = attempts.can_retry()
        assert not can_retry
        assert "Non-retryable" in reason

    def test_can_retry_max_retries_exhausted(self):
        """Should stop retrying after max attempts."""
        attempts = SettlementAttempts(nonce="test-nonce", config=RetryConfig(max_retries_preflight=2))
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        # Attempt 1
        attempts.add_attempt(error=error, tx_hash=None)
        can_retry_1, _ = attempts.can_retry()
        assert can_retry_1

        # Attempt 2
        attempts.add_attempt(error=error, tx_hash=None)
        can_retry_2, reason = attempts.can_retry()
        assert not can_retry_2
        assert "Max retries" in reason


class TestErrorLogging:
    """Test logging level determination."""

    def test_first_attempt_transient_error_logs_as_warning(self):
        """First attempt of transient error should log as warning."""
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        should_error = should_log_as_error(error, attempt_num=1)
        assert not should_error  # Should be warning, not error

    def test_first_attempt_permanent_error_logs_as_error(self):
        """First attempt of permanent error should log as error."""
        error = SettlementError(SettlementErrorType.INVALID_SIGNATURE, "test")

        should_error = should_log_as_error(error, attempt_num=1)
        assert should_error

    def test_multiple_attempts_permanent_error_logs_as_error(self):
        """Multiple attempts of transient error should eventually log as error."""
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        should_error = should_log_as_error(error, attempt_num=2)
        assert should_error  # Upgraded to error on retry


class TestSettlementFlow:
    """Integration tests for settlement flow."""

    def test_successful_settlement_first_attempt(self):
        """Settlement succeeds on first attempt."""
        attempts = SettlementAttempts(nonce="test")

        attempt = attempts.add_attempt(error=None, tx_hash="0xabc")

        assert len(attempts.attempts) == 1
        assert attempt.succeeded
        assert attempts.summary()["total_attempts"] == 1
        assert attempts.summary()["succeeded"]

    def test_settlement_succeeds_after_retry(self):
        """Settlement fails once then succeeds."""
        attempts = SettlementAttempts(nonce="test", config=RetryConfig())
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        # First attempt fails
        attempts.add_attempt(error=error, tx_hash=None)

        can_retry, _ = attempts.can_retry()
        assert can_retry

        # Second attempt succeeds
        attempts.add_attempt(error=None, tx_hash="0xdef")

        summary = attempts.summary()
        assert summary["total_attempts"] == 2
        assert summary["succeeded"]
        assert summary["first_error"] == "balance_insufficient"
        assert summary["final_tx_hash"] == "0xdef"

    def test_settlement_exhausts_retries(self):
        """Settlement fails after exhausting retries."""
        config = RetryConfig(max_retries_preflight=2)
        attempts = SettlementAttempts(nonce="test", config=config)
        error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "test")

        # Three attempts, all fail
        for i in range(3):
            attempts.add_attempt(error=error, tx_hash=None)

        summary = attempts.summary()
        assert summary["total_attempts"] == 3
        assert not summary["succeeded"]
        assert summary["last_error"] == "balance_insufficient"


# ============================================================================
# Real-world simulation tests
# ============================================================================


class TestRealWorldScenarios:
    """Simulate real-world failure scenarios."""

    def test_scenario_transient_rpc_failure(self):
        """RPC temporarily unavailable, recovers on retry."""
        attempts = SettlementAttempts(nonce="test", config=RetryConfig())

        # Attempt 1: RPC error
        rpc_error = SettlementError(SettlementErrorType.RPC_UNAVAILABLE, "Connection timeout")
        attempts.add_attempt(error=rpc_error, tx_hash=None)

        can_retry, _ = attempts.can_retry()
        assert can_retry

        # Wait simulated backoff
        delay = attempts.get_retry_delay_ms()
        assert delay == 100  # Initial delay

        # Attempt 2: Success
        attempts.add_attempt(error=None, tx_hash="0x123")

        summary = attempts.summary()
        assert summary["succeeded"]
        assert summary["first_error"] == "rpc_unavailable"

    def test_scenario_balance_changes_between_calls(self):
        """Balance insufficient in preflight but sufficient later."""
        attempts = SettlementAttempts(nonce="test", config=RetryConfig())

        # Attempt 1: Preflight says insufficient (may skip preflight on retry)
        balance_error = SettlementError(SettlementErrorType.BALANCE_INSUFFICIENT, "Payer has insufficient balance")
        attempts.add_attempt(error=balance_error, tx_hash=None)

        # Check that next attempt should skip preflight
        assert attempts.last_error.should_skip_preflight_on_retry

        can_retry, _ = attempts.can_retry()
        assert can_retry

        # Attempt 2: Success (skipping preflight allowed state change to be detected)
        attempts.add_attempt(error=None, tx_hash="0x456")

        summary = attempts.summary()
        assert summary["succeeded"]
        assert len(summary["attempts_details"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
