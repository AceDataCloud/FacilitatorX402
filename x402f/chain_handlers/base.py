"""
Base chain handler interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass


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


class ChainHandler(ABC):
    """
    Abstract base class for blockchain payment handlers.
    Each blockchain (Base, Solana, etc.) implements this interface.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the chain handler.

        Args:
            config: Chain-specific configuration (RPC URL, signer keys, etc.)
        """
        self.config = config

    @property
    @abstractmethod
    def chain_name(self) -> str:
        """Return the chain name (e.g., 'base', 'solana')."""
        pass

    @abstractmethod
    def verify_signature(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> VerificationResult:
        """
        Verify the payment authorization signature.

        Args:
            payload: Payment payload from client
            requirements: Payment requirements

        Returns:
            VerificationResult with validation status and payer address
        """
        pass

    @abstractmethod
    def settle_payment(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> SettlementResult:
        """
        Settle the payment on-chain (execute the transfer).

        Args:
            payload: Payment payload from client
            requirements: Payment requirements

        Returns:
            SettlementResult with transaction hash and status
        """
        pass

    @abstractmethod
    def validate_address(self, address: str) -> bool:
        """
        Validate if the address format is correct for this chain.

        Args:
            address: Address to validate

        Returns:
            True if valid, False otherwise
        """
        pass

    def get_explorer_url(self, tx_hash: str) -> str:
        """
        Get block explorer URL for transaction.

        Args:
            tx_hash: Transaction hash

        Returns:
            Explorer URL
        """
        return f"{self.config.get('explorer_url', '')}/tx/{tx_hash}"
