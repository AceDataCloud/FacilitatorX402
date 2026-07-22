from collections.abc import Callable
from dataclasses import dataclass

from django.conf import settings
from x402 import x402FacilitatorSync
from x402.mechanisms.evm.exact import ExactEvmFacilitatorScheme
from x402.mechanisms.evm.signer import FacilitatorEvmSigner
from x402.mechanisms.evm.upto import UptoEvmFacilitatorScheme
from x402.mechanisms.svm.constants import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from x402.mechanisms.svm.exact import ExactSvmFacilitatorScheme
from x402.mechanisms.svm.signer import FacilitatorSvmSigner
from x402.schemas import SupportedKind, SupportedResponse

from x402f.official_signer import DurableFacilitatorSvmSigner, DurableFacilitatorWeb3Signer

BASE_MAINNET = "eip155:8453"
BASE_MAINNET_CHAIN_ID = 8453
SKALE_MAINNET = "eip155:1187947933"
ROBINHOOD_MAINNET = "eip155:4663"


@dataclass(frozen=True)
class ConfiguredFacilitator:
    facilitator: x402FacilitatorSync
    signers: dict[str, FacilitatorEvmSigner | FacilitatorSvmSigner]

    def signer_for(self, network: str):  # noqa: ANN201
        try:
            return self.signers[network]
        except KeyError as exc:
            raise RuntimeError(f"No facilitator signer is configured for {network}") from exc


def configured_base_network() -> str:
    return settings.X402_BASE_NETWORK


def configured_base_chain_id() -> int:
    return settings.X402_BASE_CHAIN_ID


def register_evm_schemes(
    facilitator: x402FacilitatorSync,
    signer: FacilitatorEvmSigner,
    networks: list[str],
    *,
    exact: bool = True,
    upto: bool = False,
) -> None:
    if exact:
        facilitator.register(networks, ExactEvmFacilitatorScheme(signer))
    if upto:
        facilitator.register(networks, UptoEvmFacilitatorScheme(signer))


def register_svm_exact(
    facilitator: x402FacilitatorSync,
    signer: FacilitatorSvmSigner,
    networks: list[str],
) -> None:
    facilitator.register(networks, ExactSvmFacilitatorScheme(signer))


def build_facilitator(
    signer: FacilitatorEvmSigner,
    network: str | None = None,
    *,
    enable_upto: bool = False,
) -> x402FacilitatorSync:
    facilitator = x402FacilitatorSync()
    register_evm_schemes(
        facilitator,
        signer,
        [network or configured_base_network()],
        upto=enable_upto,
    )
    return facilitator


def build_configured_facilitator(
    on_transaction_prepared: Callable[[str, str, int | None], None] | None = None,
    on_transaction_broadcast: Callable[[str], None] | None = None,
    network: str | None = None,
) -> tuple[x402FacilitatorSync, FacilitatorEvmSigner | FacilitatorSvmSigner]:
    configured = build_configured_registry(
        on_transaction_prepared,
        on_transaction_broadcast,
        networks={network} if network else None,
    )
    configured.facilitator._acedata_signers = configured.signers
    default_signer = configured.signers.get(configured_base_network()) or next(iter(configured.signers.values()))
    return configured.facilitator, default_signer


def _evm_signer(
    *,
    label: str,
    rpc_url: str,
    private_key: str,
    address: str,
    chain_id: int,
    gas_limit: int,
    on_transaction_prepared: Callable[[str, str, int], None] | None,
    on_transaction_broadcast: Callable[[str], None] | None,
) -> DurableFacilitatorWeb3Signer:
    if not rpc_url or not private_key:
        raise RuntimeError(f"{label} facilitator RPC and signer must be configured")
    signer = DurableFacilitatorWeb3Signer(
        private_key=private_key,
        rpc_url=rpc_url,
        gas_limit=gas_limit,
        receipt_timeout=settings.X402_TX_TIMEOUT_SECONDS,
        chain_id=chain_id,
        on_transaction_prepared=on_transaction_prepared,
        on_transaction_broadcast=on_transaction_broadcast,
    )
    if address and address.lower() != signer.address.lower():
        raise RuntimeError(f"Configured {label} signer address does not match private key")
    return signer


def _svm_signer(
    *,
    label: str,
    rpc_url: str,
    private_key: str,
    address: str,
    on_transaction_prepared: Callable[[str, str, int | None], None] | None,
    on_transaction_broadcast: Callable[[str], None] | None,
) -> DurableFacilitatorSvmSigner:
    if not rpc_url or not private_key:
        raise RuntimeError(f"{label} facilitator RPC and signer must be configured")
    signer = DurableFacilitatorSvmSigner(
        private_key,
        rpc_url,
        on_transaction_prepared=on_transaction_prepared,
        on_transaction_broadcast=on_transaction_broadcast,
    )
    actual = signer.get_addresses()[0]
    if address and address != actual:
        raise RuntimeError(f"Configured {label} signer address does not match private key")
    return signer


def build_configured_registry(
    on_transaction_prepared: Callable[[str, str, int | None], None] | None = None,
    on_transaction_broadcast: Callable[[str], None] | None = None,
    networks: set[str] | None = None,
) -> ConfiguredFacilitator:
    facilitator = x402FacilitatorSync()
    signers: dict[str, FacilitatorEvmSigner | FacilitatorSvmSigner] = {}

    if (settings.X402_BASE_EXACT_ENABLED or settings.X402_BASE_UPTO_ENABLED) and (
        networks is None or settings.X402_BASE_NETWORK in networks
    ):
        signer = _evm_signer(
            label="Base",
            rpc_url=settings.X402_BASE_RPC_URL,
            private_key=settings.X402_BASE_SIGNER_PRIVATE_KEY,
            address=settings.X402_BASE_SIGNER_ADDRESS,
            chain_id=settings.X402_BASE_CHAIN_ID,
            gas_limit=max(settings.X402_GAS_LIMIT, 500000),
            on_transaction_prepared=on_transaction_prepared,
            on_transaction_broadcast=on_transaction_broadcast,
        )
        signers[settings.X402_BASE_NETWORK] = signer
        register_evm_schemes(
            facilitator,
            signer,
            [settings.X402_BASE_NETWORK],
            exact=settings.X402_BASE_EXACT_ENABLED,
            upto=settings.X402_BASE_UPTO_ENABLED,
        )

    if settings.X402_SKALE_EXACT_ENABLED and (networks is None or SKALE_MAINNET in networks):
        signer = _evm_signer(
            label="SKALE",
            rpc_url=settings.X402_SKALE_RPC_URL,
            private_key=settings.X402_SKALE_SIGNER_PRIVATE_KEY,
            address=settings.X402_SKALE_SIGNER_ADDRESS,
            chain_id=settings.X402_SKALE_CHAIN_ID,
            gas_limit=settings.X402_SKALE_GAS_LIMIT,
            on_transaction_prepared=on_transaction_prepared,
            on_transaction_broadcast=on_transaction_broadcast,
        )
        signers[SKALE_MAINNET] = signer
        register_evm_schemes(facilitator, signer, [SKALE_MAINNET])

    if settings.X402_ROBINHOOD_EXACT_ENABLED and (networks is None or ROBINHOOD_MAINNET in networks):
        signer = _evm_signer(
            label="Robinhood Chain",
            rpc_url=settings.X402_ROBINHOOD_RPC_URL,
            private_key=settings.X402_ROBINHOOD_SIGNER_PRIVATE_KEY,
            address=settings.X402_ROBINHOOD_SIGNER_ADDRESS,
            chain_id=settings.X402_ROBINHOOD_CHAIN_ID,
            gas_limit=settings.X402_ROBINHOOD_GAS_LIMIT,
            on_transaction_prepared=on_transaction_prepared,
            on_transaction_broadcast=on_transaction_broadcast,
        )
        signers[ROBINHOOD_MAINNET] = signer
        register_evm_schemes(facilitator, signer, [ROBINHOOD_MAINNET])

    solana_settings = (
        (
            settings.X402_SOLANA_MAINNET_ENABLED,
            "Solana mainnet",
            SOLANA_MAINNET_CAIP2,
            settings.X402_SOLANA_RPC_URL,
            settings.X402_SOLANA_SIGNER_PRIVATE_KEY,
            settings.X402_SOLANA_SIGNER_ADDRESS,
        ),
        (
            settings.X402_SOLANA_DEVNET_ENABLED,
            "Solana devnet",
            SOLANA_DEVNET_CAIP2,
            settings.X402_SOLANA_DEVNET_RPC_URL,
            settings.X402_SOLANA_DEVNET_SIGNER_PRIVATE_KEY,
            settings.X402_SOLANA_DEVNET_SIGNER_ADDRESS,
        ),
    )
    for enabled, label, network, rpc_url, private_key, address in solana_settings:
        if not enabled or (networks is not None and network not in networks):
            continue
        signer = _svm_signer(
            label=label,
            rpc_url=rpc_url,
            private_key=private_key,
            address=address,
            on_transaction_prepared=on_transaction_prepared,
            on_transaction_broadcast=on_transaction_broadcast,
        )
        signers[network] = signer
        register_svm_exact(facilitator, signer, [network])

    if not signers:
        raise RuntimeError("No x402 facilitator payment kinds are enabled")
    return ConfiguredFacilitator(facilitator, signers)


def configured_supported_response() -> SupportedResponse:
    kinds: list[SupportedKind] = []
    evm_addresses: list[str] = []
    svm_addresses: list[str] = []

    if settings.X402_BASE_EXACT_ENABLED:
        kinds.append(SupportedKind(x402Version=2, scheme="exact", network=settings.X402_BASE_NETWORK))
    if settings.X402_BASE_UPTO_ENABLED:
        if not settings.X402_BASE_SIGNER_ADDRESS:
            raise RuntimeError("Base upto requires a configured facilitator address")
        kinds.append(
            SupportedKind(
                x402Version=2,
                scheme="upto",
                network=settings.X402_BASE_NETWORK,
                extra={"facilitatorAddress": settings.X402_BASE_SIGNER_ADDRESS},
            )
        )
    if settings.X402_BASE_EXACT_ENABLED or settings.X402_BASE_UPTO_ENABLED:
        if not settings.X402_BASE_SIGNER_ADDRESS:
            raise RuntimeError("Base requires a configured signer address")
        evm_addresses.append(settings.X402_BASE_SIGNER_ADDRESS)
    if settings.X402_SKALE_EXACT_ENABLED:
        if not settings.X402_SKALE_SIGNER_ADDRESS:
            raise RuntimeError("SKALE requires a configured signer address")
        kinds.append(SupportedKind(x402Version=2, scheme="exact", network=SKALE_MAINNET))
        evm_addresses.append(settings.X402_SKALE_SIGNER_ADDRESS)
    if settings.X402_ROBINHOOD_EXACT_ENABLED:
        if not settings.X402_ROBINHOOD_SIGNER_ADDRESS:
            raise RuntimeError("Robinhood Chain requires a configured signer address")
        kinds.append(SupportedKind(x402Version=2, scheme="exact", network=ROBINHOOD_MAINNET))
        evm_addresses.append(settings.X402_ROBINHOOD_SIGNER_ADDRESS)
    if settings.X402_SOLANA_MAINNET_ENABLED:
        if not settings.X402_SOLANA_SIGNER_ADDRESS:
            raise RuntimeError("Solana mainnet requires a configured fee payer")
        kinds.append(
            SupportedKind(
                x402Version=2,
                scheme="exact",
                network=SOLANA_MAINNET_CAIP2,
                extra={"feePayer": settings.X402_SOLANA_SIGNER_ADDRESS},
            )
        )
        svm_addresses.append(settings.X402_SOLANA_SIGNER_ADDRESS)
    if settings.X402_SOLANA_DEVNET_ENABLED:
        devnet_address = settings.X402_SOLANA_DEVNET_SIGNER_ADDRESS
        if not devnet_address:
            raise RuntimeError("Solana devnet requires a configured fee payer")
        kinds.append(
            SupportedKind(
                x402Version=2,
                scheme="exact",
                network=SOLANA_DEVNET_CAIP2,
                extra={"feePayer": devnet_address},
            )
        )
        svm_addresses.append(devnet_address)
    if not kinds:
        raise RuntimeError("No x402 facilitator payment kinds are enabled")
    signers = {}
    if evm_addresses:
        signers["eip155:*"] = list(dict.fromkeys(evm_addresses))
    if svm_addresses:
        signers["solana:*"] = list(dict.fromkeys(svm_addresses))
    return SupportedResponse(kinds=kinds, signers=signers)
