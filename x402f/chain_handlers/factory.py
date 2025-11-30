"""
Factory for creating chain handlers.
"""
from typing import Dict, Any, Type
from .base import ChainHandler
from .base_chain import BaseChainHandler
from .solana_chain import SolanaChainHandler


class ChainHandlerFactory:
    """Factory to create chain handlers based on network name."""

    _handlers: Dict[str, Type[ChainHandler]] = {
        'base': BaseChainHandler,
        'solana': SolanaChainHandler,
        'solana-devnet': SolanaChainHandler,
    }

    @classmethod
    def create(cls, network: str, config: Dict[str, Any] = None) -> ChainHandler:
        """
        Create a chain handler for the specified network.

        Args:
            network: Network name ('base', 'solana', etc.)
            config: Optional configuration dict (RPC URL, signer keys, etc.)

        Returns:
            ChainHandler instance

        Raises:
            ValueError: If network is not supported
        """
        network_lower = network.lower().strip()

        handler_class = cls._handlers.get(network_lower)
        if handler_class is None:
            supported = ', '.join(cls._handlers.keys())
            raise ValueError(
                f"Unsupported network: {network}. "
                f"Supported networks: {supported}"
            )

        return handler_class(config or {})

    @classmethod
    def register(cls, network: str, handler_class: Type[ChainHandler]) -> None:
        """
        Register a new chain handler.

        Args:
            network: Network name
            handler_class: ChainHandler subclass
        """
        cls._handlers[network.lower().strip()] = handler_class

    @classmethod
    def get_supported_networks(cls) -> list[str]:
        """Get list of supported network names."""
        return list(cls._handlers.keys())
