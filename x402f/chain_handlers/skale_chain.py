"""
SKALE chain handler for EVM-based SKALE Base network.

SKALE Base is an EVM-compatible Layer 1 with zero gas fees, bridged from Base.
It uses the same EIP-712 / ERC-3009 transferWithAuthorization pattern as Base,
but with a different Chain ID, RPC endpoint, and bridged USDC.e token address.
"""

from typing import Any, Dict

from loguru import logger
from web3 import HTTPProvider, Web3

from .base_chain import BaseChainHandler


class SkaleChainHandler(BaseChainHandler):
    """Handler for SKALE Base blockchain (zero gas fees, EVM-compatible)."""

    CHAIN_ID = 1187947933  # SKALE Base mainnet

    def __init__(self, config: Dict[str, Any]):
        # Call grandparent (ChainHandler) init directly to avoid BaseChainHandler
        # pulling Base-specific legacy fallback settings.
        from .base import ChainHandler

        ChainHandler.__init__(self, config)

        from django.conf import settings

        self.rpc_url = config.get("rpc_url") or getattr(settings, "X402_SKALE_RPC_URL", "")
        self.signer_private_key = config.get("signer_private_key") or getattr(
            settings, "X402_SKALE_SIGNER_PRIVATE_KEY", ""
        )
        self.signer_address = config.get("signer_address") or getattr(settings, "X402_SKALE_SIGNER_ADDRESS", "")
        self.gas_limit = config.get("gas_limit", 250000)
        self.tx_timeout_seconds = config.get("tx_timeout_seconds", 120)
        # SKALE has zero gas fees, but we still set these for EVM compatibility
        self.max_fee_per_gas_wei = config.get("max_fee_per_gas_wei", 0)
        self.max_priority_fee_per_gas_wei = config.get("max_priority_fee_per_gas_wei", 0)

    @property
    def chain_name(self) -> str:
        return "skale"

    def _map_contract_error(self, exc: Exception) -> str:
        """Map contract errors to user-friendly messages."""
        message = str(exc).lower()
        if "amount exceeds balance" in message or "insufficient balance" in message:
            return "Payer has insufficient USDC.e balance on SKALE"
        if "insufficient funds" in message:
            return "Facilitator has insufficient credits on SKALE"
        return "Settlement transaction reverted on-chain"

    def get_explorer_url(self, tx_hash: str) -> str:
        """Get SKALE Base Explorer URL."""
        return f"https://skale-base-explorer.skalenodes.com/tx/{tx_hash}"
