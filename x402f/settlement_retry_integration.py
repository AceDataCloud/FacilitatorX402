"""
Enhanced X402 Settlement View with Retry Logic

This is a comprehensive patch for views.py that implements:
1. Smart retry with exponential backoff for transient errors
2. Better error classification (preflight vs on-chain vs RPC)
3. Configurable retry strategies per error type
4. Better logging and diagnostics
5. Recovery mechanism for completed transactions
"""

import time
from functools import wraps

from django.conf import settings
from loguru import logger

from .settlement_enhancements import (
    RetryConfig,
    SettlementAttempts,
    SettlementError,
    classify_error,
    should_log_as_error,
)


def get_retry_config() -> RetryConfig:
    """Get retry configuration from Django settings or defaults."""
    custom_config = getattr(settings, "X402_RETRY_CONFIG", {})
    config = RetryConfig()

    for key, value in custom_config.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return config


def retry_settlement_with_backoff(func):
    """
    Decorator to add retry logic with exponential backoff to settlement functions.

    Usage:
        @retry_settlement_with_backoff
        def settle_payment_on_chain(data: ValidatedAuthorization) -> str:
            # ... settlement logic ...

    The decorated function should:
    - Return tx_hash (str) on success
    - Raise SettlementError on failure (will trigger retries if retryable)
    - Raise other exceptions for non-retry errors
    """

    @wraps(func)
    def wrapper(data, skip_preflight: bool = False):
        config = get_retry_config()
        attempts = SettlementAttempts(nonce=data.nonce, config=config)

        while True:
            attempt = len(attempts.attempts) + 1

            try:
                logger.debug(
                    "x402 settlement attempt {} for nonce {} (skip_preflight={})",
                    attempt,
                    data.nonce,
                    skip_preflight,
                )

                # Call the actual settlement function
                # Note: In real implementation, we'd pass skip_preflight to the function
                # so it can skip preflight checks if requested
                tx_hash = func(data, skip_preflight=skip_preflight)

                # Success!
                attempts.add_attempt(error=None, tx_hash=tx_hash)
                logger.info(
                    "x402 settlement succeeded on attempt {} for nonce {} with tx {}",
                    attempt,
                    data.nonce,
                    tx_hash,
                )
                return tx_hash

            except SettlementError as exc:
                # Known settlement error - classify and potentially retry
                error = exc if isinstance(exc, SettlementError) else classify_error(exc)
                attempts.add_attempt(error=error, tx_hash=None)

                # Log appropriately based on attempt count and error type
                log_func = logger.error if should_log_as_error(error, attempt) else logger.warning
                log_func(
                    "x402 settlement failed on attempt {} for nonce {}: {} (retryable={}, error_type={})",
                    attempt,
                    data.nonce,
                    error.message,
                    error.is_retryable,
                    error.error_type.value,
                )

                # Check if we should retry
                can_retry, reason = attempts.can_retry()
                if not can_retry:
                    logger.error(
                        "x402 settlement abandoned after {} attempts for nonce {}: {}",
                        attempt,
                        data.nonce,
                        reason,
                    )
                    raise error

                # Calculate backoff delay
                delay_ms = attempts.get_retry_delay_ms()
                logger.info(
                    "x402 settlement will retry in {}ms (attempt {} of {})",
                    delay_ms,
                    attempt + 1,
                    config.get_max_retries(error.error_type),
                )

                # Sleep before retry
                time.sleep(delay_ms / 1000.0)

                # Decide if we should skip preflight on next attempt
                # Skipping preflight on retry of balance errors since state may have changed
                if error.should_skip_preflight_on_retry:
                    skip_preflight = True

            except Exception as exc:
                # Unexpected error - don't retry
                error = classify_error(exc)
                attempts.add_attempt(error=error, tx_hash=None)

                logger.error(
                    "x402 settlement failed with unexpected error on attempt {} for nonce {}: {}",
                    attempt,
                    data.nonce,
                    str(exc),
                )
                raise error

    return wrapper


# ============================================================================
# Helper function to integrate with existing views.py
# ============================================================================


def create_recovery_record(nonce: str, error: SettlementError, submitted_nonce: bool = False) -> dict:
    """
    Create a recovery record for debugging/transparency.

    This can be stored in metadata of X402Authorization model or elsewhere
    for debugging purposes.
    """
    recovery_info = {
        "nonce": nonce,
        "error_type": error.error_type.value,
        "error_message": error.message,
        "is_retryable": error.is_retryable,
        "details": error.details,
        "timestamp": time.time(),
    }

    if submitted_nonce:
        recovery_info["note"] = (
            "Nonce was submitted to blockchain. Check on-chain status before retrying. "
            "Use GET /x402/recover/<nonce> to query status."
        )

    return recovery_info


# ============================================================================
# Example integration in X402SettleView (pseudo-code for documentation)
# ============================================================================

"""
INTEGRATION PATTERN for existing X402SettleView.post():

    try:
        payload, requirements = _parse_payload(request.data)
        validated = _validate_payload(payload, requirements)
    except ... as exc:
        # validation errors remain unchanged
        ...
    
    try:
        # NEW: Use retry decorator for settlement
        tx_hash = settle_payment_with_retries(validated)
        
        # Mark as settled (unchanged)
        with transaction.atomic():
            record = X402Authorization.objects.select_for_update().get(nonce=validated.nonce)
            # ... existing settlement checks ...
            record.mark_settled(tx_hash)
            record.save(...)
        
        return Response({"success": True, ...})
    
    except SettlementError as exc:
        # Classify and return appropriate response
        log_level = "error" if not exc.is_retryable else "warning"
        getattr(logger, log_level)(
            "x402 settlement final failure for nonce {}: {} (type={})",
            validated.nonce,
            exc.message,
            exc.error_type.value,
        )
        
        # Create recovery record if needed
        if exc.is_retryable:
            recovery = create_recovery_record(validated.nonce, exc)
            # Store in X402Authorization.metadata["recovery"] for later retrieval
        
        return Response(
            {
                "success": False,
                "errorReason": exc.message,
                "errorType": exc.error_type.value,
                "isRetryable": exc.is_retryable,
                "recoveryInfo": recovery if exc.is_retryable else None,
            },
            status=status.HTTP_200_OK,
        )
"""
