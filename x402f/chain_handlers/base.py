"""Base chain handler interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional


@dataclass
class VerificationResult:
    """Result of payment verification."""

    is_valid: bool
    payer: Optional[str] = None
    invalid_reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class SettlementResult:
    """Result of payment settlement."""

    success: bool
    transaction_hash: Optional[str] = None
    payer: Optional[str] = None
    error_reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class TransactionStatus(str, Enum):
    CONFIRMED = "confirmed"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ChainHandler(ABC):
    """Abstract interface implemented by every supported payment chain."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @property
    @abstractmethod
    def chain_name(self) -> str:
        pass

    @abstractmethod
    def verify_signature(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> VerificationResult:
        pass

    @abstractmethod
    def settle_payment(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
        on_transaction_prepared: Optional[Callable[[str], None]] = None,
    ) -> SettlementResult:
        """Submit settlement, persisting its deterministic hash before broadcast."""
        pass

    @abstractmethod
    def validate_address(self, address: str) -> bool:
        pass

    def get_transaction_status(self, tx_hash: str) -> TransactionStatus:
        return TransactionStatus.UNKNOWN

    def check_transaction_status(self, tx_hash: str) -> bool:
        """Backward-compatible boolean status check."""
        return self.get_transaction_status(tx_hash) == TransactionStatus.CONFIRMED

    def get_explorer_url(self, tx_hash: str) -> str:
        return f"{self.config.get('explorer_url', '')}/tx/{tx_hash}"
