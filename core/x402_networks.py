"""Native USDC networks available for opt-in x402 exact payments."""

EVM_EXACT_NETWORKS = {
    "arbitrum": (42161, "Arbitrum One", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    "polygon": (137, "Polygon PoS", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
    "optimism": (10, "OP Mainnet", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
}


def load_evm_exact_networks(env):
    """Keep new rails off until their own recipient is explicitly configured."""
    networks = {}
    for alias, (chain_id, label, asset) in EVM_EXACT_NETWORKS.items():
        prefix = f"X402_{alias.upper()}"
        if not env.bool(f"{prefix}_EXACT_ENABLED", False):
            continue
        pay_to = env.str(f"{prefix}_PAY_TO", "")
        if len(pay_to) != 42 or not pay_to.startswith("0x"):
            raise ValueError(f"{prefix}_PAY_TO must be an EVM address")
        try:
            int(pay_to[2:], 16)
        except ValueError as exc:
            raise ValueError(f"{prefix}_PAY_TO must be an EVM address") from exc
        if int(pay_to[2:], 16) == 0:
            raise ValueError(f"{prefix}_PAY_TO must not be the zero address")
        networks[f"eip155:{chain_id}"] = {
            "alias": alias,
            "label": label,
            "chain_id": chain_id,
            "asset": asset,
            "pay_to": pay_to,
        }
    return networks
