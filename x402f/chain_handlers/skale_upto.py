"""Handler for the x402 `upto` scheme on SKALE Base.

SKALE Base is a zero-gas-fee EVM-compatible chain. The Permit2 contract and
the x402 upto proxy are deployed at the same CREATE2 address as on Base, so
this class only exists to namespace the (network, scheme) -> handler mapping
and to give us a clean place to add SKALE-specific behaviour (zero-gas
settle, bridged-USDC quirks) if needed in the future.
"""

from __future__ import annotations

from .base_upto import BaseUptoHandler


class SkaleUptoHandler(BaseUptoHandler):
    """Handler for the x402 `upto` scheme on SKALE Base."""
