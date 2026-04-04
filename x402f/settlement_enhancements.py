"""
X402 Settlement Enhancements

Fixes:
1. RPC Time-of-Check-Time-of-Use (TOCTOU) gap: Preflight check can fail while actual
   tx succeeds due to state changes between call() and send_raw_transaction()
2. Missing retry logic: Transient RPC errors cause immediate failure with no recovery
3. Insufficient error classification: Can't distinguish preflight vs on-chain vs RPC errors
4. No transaction recovery: Successfully submitted txs aren't recovered if facilitator crashes

Implementation:
- Separate preflight and submission errors with aggressive retries for transient RPC issues
- Add configurable retry strategy (exponential backoff for RPC, immediate for state changes)
- Classify errors: Preflight-only (safe to retry) vs Submission (risky to retry, needs verification)
- Add recovery endpoint to check on-chain status of previously submitted nonces
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple

from loguru import logger
from web3.exceptions import BadFunctionCallOutput, ContractLogicError


class SettlementErrorType(Enum):
    """Classification of settlement errors."""

    # Preflight errors - safe to retry (state can change between preflight and submission)
    BALANCE_INSUFFICIENT = "balance_insufficient"  # RPC showed insufficient balance but state may change
    GAS_ESTIMATION_FAILED = "gas_estimation_failed"  # Can fail for transient reasons
    RPC_UNAVAILABLE = "rpc_unavailable"  # Temporary RPC connectivity issues

    # Mixed errors (could be either preflight or on-chain)
    CONTRACT_REVERTED = "contract_reverted"  # Could be actual contract error or state change

    # On-chain errors - NOT safe to retry
    TX_TIMEOUT = "tx_timeout"  # Settlement timed out, transaction may still be pending
    INVALID_SIGNATURE = "invalid_signature"  # Signature doesn't match
    NONCE_USED = "nonce_used"  # Nonce already processed
    INVALID_PARAMS = "invalid_params"  # Request validation failed
    SIGNER_MISCONFIGURED = "signer_misconfigured"  # Facilitator configuration error

    # Unknown
    UNKNOWN = "unknown"


@dataclass
class RetryConfig:
    """Configuration for retry strategy."""

    # Maximum retry attempts for specific error types
    max_retries_preflight: int = 3  # Aggressive retries for preflight errors
    max_retries_balance: int = 5  # Extra retries for balance-related transient issues
    max_retries_rpc: int = 4  # Retries for RPC connectivity issues

    # Backoff strategy
    initial_delay_ms: float = 100  # Start with 100ms
    max_delay_ms: float = 5000  # Cap at 5 seconds
    backoff_factor: float = 2.0  # Exponential backoff multiplier

    # Error-specific overrides
    error_max_retries: dict = field(
        default_factory=lambda: {
            SettlementErrorType.BALANCE_INSUFFICIENT: 5,
            SettlementErrorType.RPC_UNAVAILABLE: 4,
            SettlementErrorType.GAS_ESTIMATION_FAILED: 3,
        }
    )

    def get_max_retries(self, error_type: SettlementErrorType) -> int:
        """Get max retries for this error type."""
        return self.error_max_retries.get(error_type, self.max_retries_preflight)

    def get_delay_ms(self, attempt: int) -> float:
        """Calculate delay for retry attempt (0-indexed)."""
        delay = self.initial_delay_ms * (self.backoff_factor**attempt)
        return min(delay, self.max_delay_ms)


@dataclass
class SettlementError:
    """Enhanced error with classification and retry guidance."""

    error_type: SettlementErrorType
    message: str
    original_error: Optional[Exception] = None
    details: dict = field(default_factory=dict)

    @property
    def is_retryable(self) -> bool:
        """Can this error be retried (state may have changed)?"""
        return self.error_type in {
            SettlementErrorType.BALANCE_INSUFFICIENT,
            SettlementErrorType.GAS_ESTIMATION_FAILED,
            SettlementErrorType.RPC_UNAVAILABLE,
            SettlementErrorType.CONTRACT_REVERTED,  # Could be either, should retry once
        }

    @property
    def is_preflight_only(self) -> bool:
        """Error happened only in preflight check, not in actual tx?"""
        return self.error_type in {
            SettlementErrorType.BALANCE_INSUFFICIENT,
            SettlementErrorType.GAS_ESTIMATION_FAILED,
        }

    @property
    def should_skip_preflight_on_retry(self) -> bool:
        """Skip preflight on next retry to avoid same error?"""
        return self.error_type in {
            SettlementErrorType.BALANCE_INSUFFICIENT,  # Balance may have changed, skip 2nd preflight
        }

    def __str__(self) -> str:
        return f"SettlementError[{self.error_type.value}]: {self.message}"


@dataclass
class Attempt:
    """Single settlement attempt record."""

    attempt_num: int  # 1-indexed
    error: Optional[SettlementError] = None
    tx_hash: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def succeeded(self) -> bool:
        return self.tx_hash is not None and self.error is None

    @property
    def failed(self) -> bool:
        return self.error is not None


@dataclass
class SettlementAttempts:
    """Track multiple attempts for a single settlement."""

    nonce: str
    attempts: list = field(default_factory=list)
    config: RetryConfig = field(default_factory=RetryConfig)

    def add_attempt(self, error: Optional[SettlementError] = None, tx_hash: Optional[str] = None) -> Attempt:
        """Record a settlement attempt."""
        attempt = Attempt(
            attempt_num=len(self.attempts) + 1,
            error=error,
            tx_hash=tx_hash,
        )
        self.attempts.append(attempt)
        return attempt

    @property
    def last_attempt(self) -> Optional[Attempt]:
        return self.attempts[-1] if self.attempts else None

    @property
    def last_error(self) -> Optional[SettlementError]:
        return self.last_attempt.error if self.last_attempt else None

    def can_retry(self) -> Tuple[bool, Optional[str]]:
        """Check if another retry is allowed."""
        if not self.last_error:
            return False, "No error to retry"

        if not self.last_error.is_retryable:
            return False, f"Non-retryable error: {self.last_error.error_type.value}"

        max_retries = self.config.get_max_retries(self.last_error.error_type)
        if len(self.attempts) >= max_retries:
            return False, f"Max retries ({max_retries}) exhausted"

        return True, None

    def get_retry_delay_ms(self) -> float:
        """Get delay before next retry (0 if should not retry)."""
        can_retry, _ = self.can_retry()
        if not can_retry:
            return 0.0

        # Delay = config.get_delay_ms(attempt_count - 1)
        # Attempt 1 fails -> attempt 2 gets delay for attempt 0 (100ms)
        return self.config.get_delay_ms(len(self.attempts) - 1)

    def summary(self) -> dict:
        """Get summary of all attempts."""
        return {
            "total_attempts": len(self.attempts),
            "succeeded": any(a.succeeded for a in self.attempts),
            "first_error": self.attempts[0].error.error_type.value if self.attempts[0].error else None,
            "last_error": self.last_error.error_type.value if self.last_error else None,
            "final_tx_hash": next((a.tx_hash for a in reversed(self.attempts) if a.succeeded), None),
            "attempts_details": [
                {
                    "num": a.attempt_num,
                    "status": "success" if a.succeeded else "failed",
                    "error_type": a.error.error_type.value if a.error else None,
                    "tx_hash": a.tx_hash,
                    "timestamp": a.timestamp,
                }
                for a in self.attempts
            ],
        }


def classify_error(exc: Exception) -> SettlementError:
    """
    Classify an exception from preflight/submission into SettlementErrorType.

    This helps determine if an error is temporary (safe to retry) or permanent.
    """
    message = str(exc) or ""
    lower = message.lower()

    # Check for contract revert errors
    if isinstance(exc, ContractLogicError):
        # Insufficient balance - could be transient RPC state
        if any(p in lower for p in ["amount exceeds balance", "insufficient balance", "insufficient token"]):
            return SettlementError(
                error_type=SettlementErrorType.BALANCE_INSUFFICIENT,
                message="Payer balance reported as insufficient (may be transient RPC state).",
                original_error=exc,
                details={"error_class": "ContractLogicError", "raw_message": message},
            )

        # Insufficient gas on facilitator
        if "insufficient funds" in lower:
            return SettlementError(
                error_type=SettlementErrorType.SIGNER_MISCONFIGURED,
                message="Facilitator signer has insufficient native balance for gas.",
                original_error=exc,
                details={"error_class": "ContractLogicError", "raw_message": message},
            )

        # Generic contract revert
        return SettlementError(
            error_type=SettlementErrorType.CONTRACT_REVERTED,
            message="Settlement transaction reverted on-chain (may be transient).",
            original_error=exc,
            details={"error_class": "ContractLogicError", "raw_message": message},
        )

    # Check for RPC/connectivity errors
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return SettlementError(
            error_type=SettlementErrorType.RPC_UNAVAILABLE,
            message="RPC endpoint temporarily unavailable or timing out.",
            original_error=exc,
            details={"error_class": exc.__class__.__name__},
        )

    if "connection" in lower or "timeout" in lower or "temporarily" in lower:
        return SettlementError(
            error_type=SettlementErrorType.RPC_UNAVAILABLE,
            message="RPC connectivity issue (may be transient).",
            original_error=exc,
            details={"raw_message": message},
        )

    # Check for gas estimation failures
    if "gas estimation" in lower or "estimate_gas" in lower:
        return SettlementError(
            error_type=SettlementErrorType.GAS_ESTIMATION_FAILED,
            message="Gas estimation failed (may be due to state changes).",
            original_error=exc,
            details={"raw_message": message},
        )

    # BadFunctionCallOutput - some implementations return empty data
    if isinstance(exc, BadFunctionCallOutput):
        return SettlementError(
            error_type=SettlementErrorType.CONTRACT_REVERTED,
            message="Contract returned empty data (may indicate non-standard implementation).",
            original_error=exc,
            details={"error_class": "BadFunctionCallOutput"},
        )

    # Default to unknown
    logger.warning("Unclassified settlement error: {} ({})", exc.__class__.__name__, message)
    return SettlementError(
        error_type=SettlementErrorType.UNKNOWN,
        message=f"Unknown error: {message}",
        original_error=exc,
        details={"error_class": exc.__class__.__name__},
    )


def should_log_as_error(error: SettlementError, attempt_num: int) -> bool:
    """Determine if error should be logged as ERROR vs WARNING."""
    # First attempt of transient errors -> WARNING
    if attempt_num == 1 and error.is_retryable:
        return False

    # Non-retryable errors always -> ERROR
    if not error.is_retryable:
        return True

    # Multiple failed retries -> ERROR
    return attempt_num >= 2
