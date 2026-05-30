"""
Factory for creating chain handlers.

Dispatch key is (network, scheme). The `upto` scheme is EVM-only (Base / Skale).
"""

from typing import Any, Dict, Tuple, Type

from .base import ChainHandler
from .base_chain import BaseChainHandler
from .skale_chain import SkaleChainHandler
from .solana_chain import SolanaChainHandler
from .upto_evm import UptoEvmHandler


class ChainHandlerFactory:
    """Factory keyed by (network, scheme)."""

    _handlers: Dict[Tuple[str, str], Type[ChainHandler]] = {
        ("base", "exact"): BaseChainHandler,
        ("solana", "exact"): SolanaChainHandler,
        ("solana-devnet", "exact"): SolanaChainHandler,
        ("skale", "exact"): SkaleChainHandler,
        ("base", "upto"): UptoEvmHandler,
        ("skale", "upto"): UptoEvmHandler,
    }

    @classmethod
    def create(cls, network: str, config: Dict[str, Any] = None, scheme: str = "exact") -> ChainHandler:
        network_lower = network.lower().strip()
        scheme_lower = (scheme or "exact").lower().strip()

        handler_class = cls._handlers.get((network_lower, scheme_lower))
        if handler_class is None:
            supported = ", ".join(f"{n}/{s}" for n, s in cls._handlers.keys())
            raise ValueError(f"Unsupported (network, scheme): ({network}, {scheme}). Supported: {supported}")

        cfg = dict(config or {})
        cfg.setdefault("chain_name", network_lower)
        return handler_class(cfg)

    @classmethod
    def register(cls, network: str, scheme: str, handler_class: Type[ChainHandler]) -> None:
        cls._handlers[(network.lower().strip(), scheme.lower().strip())] = handler_class

    @classmethod
    def get_supported_networks(cls) -> list[str]:
        """Networks that have at least one scheme registered."""
        return sorted({n for (n, _s) in cls._handlers.keys()})

    @classmethod
    def get_supported_kinds(cls) -> list[Tuple[str, str]]:
        """All (network, scheme) tuples currently registered."""
        return sorted(cls._handlers.keys())
