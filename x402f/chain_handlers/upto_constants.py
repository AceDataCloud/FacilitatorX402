"""Constants and ABI fragments for the x402 `upto` scheme on EVM chains.

References:
- Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/upto/scheme_upto_evm.md
- Reference Go impl: https://github.com/x402-foundation/x402/tree/main/go/mechanisms/evm/upto
"""

# Uniswap canonical Permit2 deployment — same address on every EVM chain
# (https://docs.uniswap.org/contracts/permit2/overview)
PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# x402 foundation reference proxy contract — CREATE2-deployed at same address
# on all supported EVM chains. Verified live on Base mainnet with 42k+ Settle txs.
X402_UPTO_PERMIT2_PROXY_ADDRESS = "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"

# settle(PermitTransferFrom permit, uint256 settlementAmount, address owner,
#        X402Witness witness, bytes signature) returns (bool)
X402_UPTO_PERMIT2_PROXY_SETTLE_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {
                        "components": [
                            {"name": "token", "type": "address"},
                            {"name": "amount", "type": "uint256"},
                        ],
                        "name": "permitted",
                        "type": "tuple",
                    },
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
                "name": "permit",
                "type": "tuple",
            },
            {"name": "settlementAmount", "type": "uint256"},
            {"name": "owner", "type": "address"},
            {
                "components": [
                    {"name": "to", "type": "address"},
                    {"name": "facilitator", "type": "address"},
                    {"name": "validAfter", "type": "uint256"},
                ],
                "name": "witness",
                "type": "tuple",
            },
            {"name": "signature", "type": "bytes"},
        ],
        "name": "settle",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

# Minimal ERC-20 ABI for allowance() and balanceOf() — used by upto preflight
ERC20_READ_ABI = [
    {
        "inputs": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
        ],
        "name": "allowance",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def build_upto_permit2_typed_data(
    *,
    chain_id: int,
    permitted_token: str,
    permitted_amount: int,
    nonce: int,
    deadline: int,
    witness_to: str,
    witness_facilitator: str,
    witness_valid_after: int,
) -> dict:
    """Construct the EIP-712 typed-data dict for `PermitWitnessTransferFrom`.

    The spender is always the x402UptoPermit2Proxy; the EIP-712 domain is the
    canonical Permit2 contract (no version field — Permit2 does not include one).
    """
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PermitWitnessTransferFrom": [
                {"name": "permitted", "type": "TokenPermissions"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "witness", "type": "X402Witness"},
            ],
            "TokenPermissions": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "X402Witness": [
                {"name": "to", "type": "address"},
                {"name": "facilitator", "type": "address"},
                {"name": "validAfter", "type": "uint256"},
            ],
        },
        "primaryType": "PermitWitnessTransferFrom",
        "domain": {
            "name": "Permit2",
            "chainId": int(chain_id),
            "verifyingContract": PERMIT2_ADDRESS,
        },
        "message": {
            "permitted": {"token": permitted_token, "amount": int(permitted_amount)},
            "spender": X402_UPTO_PERMIT2_PROXY_ADDRESS,
            "nonce": int(nonce),
            "deadline": int(deadline),
            "witness": {
                "to": witness_to,
                "facilitator": witness_facilitator,
                "validAfter": int(witness_valid_after),
            },
        },
    }
