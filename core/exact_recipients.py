"""Explicit additional merchant recipients for existing mainnet exact rails."""

from django.core.exceptions import ImproperlyConfigured
from eth_utils import is_address
from solders.pubkey import Pubkey

BASE = "eip155:8453"
SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


def load_additional_exact_recipients(value: object) -> dict[str, tuple[str, ...]]:
    try:
        if not isinstance(value, dict) or set(value) - {BASE, SOLANA}:
            raise ValueError
        result = {}
        for network, addresses in value.items():
            if not isinstance(addresses, list) or len(addresses) > 32:
                raise ValueError
            normalized = []
            for address in addresses:
                if not isinstance(address, str):
                    raise ValueError
                if network == BASE:
                    if not is_address(address) or int(address, 16) == 0:
                        raise ValueError
                    address = address.lower()
                elif Pubkey.from_string(address) == Pubkey.default():
                    raise ValueError
                normalized.append(address)
            result[network] = tuple(dict.fromkeys(normalized))
        return result
    except (ValueError, TypeError):
        raise ImproperlyConfigured("Additional exact recipients require valid Base/Solana address lists") from None
