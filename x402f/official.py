from collections.abc import Callable

from django.conf import settings
from x402 import x402FacilitatorSync
from x402.mechanisms.evm.exact import ExactEvmFacilitatorScheme
from x402.mechanisms.evm.signer import FacilitatorEvmSigner

from x402f.official_signer import DurableFacilitatorWeb3Signer

BASE_MAINNET = "eip155:8453"
BASE_MAINNET_CHAIN_ID = 8453


def build_facilitator(signer: FacilitatorEvmSigner) -> x402FacilitatorSync:
    facilitator = x402FacilitatorSync()
    facilitator.register([BASE_MAINNET], ExactEvmFacilitatorScheme(signer))
    return facilitator


def build_configured_facilitator(
    on_transaction_prepared: Callable[[str, str, int], None] | None = None,
    on_transaction_broadcast: Callable[[str], None] | None = None,
) -> tuple[x402FacilitatorSync, DurableFacilitatorWeb3Signer]:
    rpc_url = settings.X402_BASE_RPC_URL
    private_key = settings.X402_BASE_SIGNER_PRIVATE_KEY
    if not rpc_url or not private_key:
        raise RuntimeError("Base facilitator RPC and signer must be configured")

    signer = DurableFacilitatorWeb3Signer(
        private_key=private_key,
        rpc_url=rpc_url,
        gas_limit=max(settings.X402_GAS_LIMIT, 500000),
        receipt_timeout=settings.X402_TX_TIMEOUT_SECONDS,
        chain_id=BASE_MAINNET_CHAIN_ID,
        on_transaction_prepared=on_transaction_prepared,
        on_transaction_broadcast=on_transaction_broadcast,
    )
    configured_address = settings.X402_BASE_SIGNER_ADDRESS
    if configured_address and configured_address.lower() != signer.address.lower():
        raise RuntimeError("Configured Base signer address does not match private key")
    return build_facilitator(signer), signer
