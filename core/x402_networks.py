"""Native USDC networks available for opt-in x402 exact payments."""

EVM_EXACT_NETWORKS = {
    "arbitrum": (42161, "Arbitrum One", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    "polygon": (137, "Polygon PoS", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
}


def load_evm_exact_networks(env):
    """Register explicitly enabled rails; recipient authorization is separate."""
    networks = {}
    for alias, (chain_id, label, asset) in EVM_EXACT_NETWORKS.items():
        prefix = f"X402_{alias.upper()}"
        if not env.bool(f"{prefix}_EXACT_ENABLED", False):
            continue
        networks[f"eip155:{chain_id}"] = {
            "alias": alias,
            "label": label,
            "chain_id": chain_id,
            "asset": asset,
        }
    return networks
