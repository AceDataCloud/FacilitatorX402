import os
import time
from unittest.mock import patch

from django.test import override_settings
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from x402.mechanisms.evm.signer import TransactionReceipt
from x402.mechanisms.svm.constants import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from x402.schemas import PaymentPayload, PaymentRequirements

from x402f.official import (
    BASE_MAINNET,
    ROBINHOOD_MAINNET,
    SKALE_MAINNET,
    build_configured_facilitator,
    build_configured_registry,
    build_facilitator,
    register_svm_exact,
)
from x402f.official_signer import DurableFacilitatorWeb3Signer

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


class FakeEvmSigner:
    def __init__(self) -> None:
        self.account = Account.create("official-facilitator")
        self.simulated_transfer = False

    def get_addresses(self) -> list[str]:
        return [self.account.address]

    def read_contract(self, address, abi, function_name, *args):  # noqa: ANN001, ANN201
        assert address.lower() == USDC_BASE.lower()
        if function_name == "transferWithAuthorization":
            self.simulated_transfer = True
            return None
        if function_name == "authorizationState":
            return False
        if function_name == "balanceOf":
            return 1_000_000
        raise AssertionError(f"unexpected contract read: {function_name}")

    def verify_typed_data(self, address, domain, types, primary_type, message, signature):  # noqa: ANN001, ANN201
        raise AssertionError("EOA verification must remain inside the official SDK")

    def write_contract(self, address, abi, function_name, *args, data_suffix=None):  # noqa: ANN001, ANN201
        raise AssertionError("verify must not broadcast")

    def send_transaction(self, to, data):  # noqa: ANN001, ANN201
        raise AssertionError("verify must not broadcast")

    def wait_for_transaction_receipt(self, tx_hash):  # noqa: ANN001, ANN201
        return TransactionReceipt(status=1, block_number=1, tx_hash=tx_hash)

    def get_balance(self, address, token_address):  # noqa: ANN001, ANN201
        return 1_000_000

    def get_chain_id(self) -> int:
        return 8453

    def get_code(self, address):  # noqa: ANN001, ANN201
        return b"\x01" if address.lower() == USDC_BASE.lower() else b""


class FakeSvmSigner:
    def __init__(self) -> None:
        self.address = str(__import__("solders.keypair").keypair.Keypair().pubkey())

    def get_addresses(self) -> list[str]:
        return [self.address]


def _payment() -> tuple[PaymentPayload, PaymentRequirements]:
    payer = Account.create("official-payer")
    pay_to = Account.create("official-payee").address
    now = int(time.time())
    nonce = "0x" + os.urandom(32).hex()
    authorization = {
        "from": payer.address,
        "to": pay_to,
        "value": "250000",
        "validAfter": str(now - 60),
        "validBefore": str(now + 600),
        "nonce": nonce,
    }
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 8453,
            "verifyingContract": USDC_BASE,
        },
        "message": {
            **authorization,
            "value": int(authorization["value"]),
            "validAfter": int(authorization["validAfter"]),
            "validBefore": int(authorization["validBefore"]),
            "nonce": HexBytes(nonce),
        },
    }
    signature = payer.sign_message(encode_typed_data(full_message=typed_data)).signature.hex()
    requirements = PaymentRequirements.model_validate(
        {
            "scheme": "exact",
            "network": BASE_MAINNET,
            "asset": USDC_BASE,
            "amount": "250000",
            "payTo": pay_to,
            "maxTimeoutSeconds": 600,
            "extra": {"name": "USD Coin", "version": "2"},
        }
    )
    payload = PaymentPayload.model_validate(
        {
            "x402Version": 2,
            "accepted": requirements.model_dump(by_alias=True),
            "payload": {
                "signature": signature,
                "authorization": authorization,
            },
        }
    )
    return payload, requirements


def test_official_base_exact_supported_and_verified() -> None:
    signer = FakeEvmSigner()
    facilitator = build_facilitator(signer)
    payload, requirements = _payment()

    supported = facilitator.get_supported().model_dump(by_alias=True)
    result = facilitator.verify(payload, requirements)

    assert supported["kinds"] == [
        {
            "x402Version": 2,
            "scheme": "exact",
            "network": BASE_MAINNET,
            "extra": None,
        }
    ]
    assert supported["signers"] == {"eip155:*": [signer.account.address]}
    assert result.is_valid is True
    assert signer.simulated_transfer is True


def test_official_canary_advertises_only_configured_sepolia_network() -> None:
    signer = FakeEvmSigner()
    facilitator = build_facilitator(signer, "eip155:84532")

    supported = facilitator.get_supported().model_dump(by_alias=True)

    assert [kind["network"] for kind in supported["kinds"]] == ["eip155:84532"]


def test_official_registry_supports_evm_exact_upto_and_svm_exact() -> None:
    evm_signer = FakeEvmSigner()
    svm_signer = FakeSvmSigner()
    facilitator = build_facilitator(evm_signer, BASE_MAINNET, enable_upto=True)
    register_svm_exact(facilitator, svm_signer, [SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2])

    supported = facilitator.get_supported().model_dump(by_alias=True)
    kinds = {(kind["scheme"], kind["network"]): kind.get("extra") for kind in supported["kinds"]}

    assert kinds[("exact", BASE_MAINNET)] is None
    assert kinds[("upto", BASE_MAINNET)] == {"facilitatorAddress": evm_signer.account.address}
    assert kinds[("exact", SOLANA_MAINNET_CAIP2)] == {"feePayer": svm_signer.address}
    assert kinds[("exact", SOLANA_DEVNET_CAIP2)] == {"feePayer": svm_signer.address}


@override_settings(
    X402_BASE_EXACT_ENABLED=True,
    X402_BASE_UPTO_ENABLED=True,
    X402_SKALE_EXACT_ENABLED=True,
    X402_ROBINHOOD_EXACT_ENABLED=True,
    X402_SOLANA_MAINNET_ENABLED=True,
    X402_SOLANA_DEVNET_ENABLED=True,
)
@patch("x402f.official._svm_signer")
@patch("x402f.official._evm_signer")
def test_configured_registry_registers_every_enabled_official_kind(evm_builder, svm_builder) -> None:
    evm_signer = FakeEvmSigner()
    svm_signer = FakeSvmSigner()
    evm_builder.return_value = evm_signer
    svm_builder.return_value = svm_signer

    configured = build_configured_registry()
    supported = configured.facilitator.get_supported().model_dump(by_alias=True)
    kinds = {(kind["scheme"], kind["network"]) for kind in supported["kinds"]}

    assert kinds == {
        ("exact", BASE_MAINNET),
        ("upto", BASE_MAINNET),
        ("exact", SKALE_MAINNET),
        ("exact", ROBINHOOD_MAINNET),
        ("exact", SOLANA_MAINNET_CAIP2),
        ("exact", SOLANA_DEVNET_CAIP2),
    }


@override_settings(
    X402_BASE_EXACT_ENABLED=True,
    X402_BASE_UPTO_ENABLED=False,
    X402_SKALE_EXACT_ENABLED=True,
    X402_SOLANA_MAINNET_ENABLED=False,
    X402_SOLANA_DEVNET_ENABLED=False,
)
@patch("x402f.official._evm_signer")
def test_configured_registry_builds_only_requested_network(evm_builder) -> None:
    evm_builder.return_value = FakeEvmSigner()

    configured = build_configured_registry(networks={BASE_MAINNET})

    assert set(configured.signers) == {BASE_MAINNET}
    assert evm_builder.call_count == 1


@override_settings(
    X402_BASE_EXACT_ENABLED=False,
    X402_BASE_UPTO_ENABLED=False,
    X402_SKALE_EXACT_ENABLED=False,
    X402_SOLANA_MAINNET_ENABLED=False,
    X402_SOLANA_DEVNET_ENABLED=False,
)
def test_configured_registry_rejects_empty_capability_set() -> None:
    with __import__("pytest").raises(RuntimeError, match="No x402 facilitator payment kinds"):
        build_configured_registry()


@override_settings(
    X402_BASE_NETWORK="eip155:84532",
    X402_BASE_CHAIN_ID=84532,
    X402_BASE_RPC_URL="https://sepolia.base.org",
    X402_BASE_SIGNER_PRIVATE_KEY="0x" + "11" * 32,
    X402_BASE_SIGNER_ADDRESS="",
)
@patch("x402f.official.DurableFacilitatorWeb3Signer")
def test_configured_canary_signer_uses_sepolia_chain_id(signer_class) -> None:
    signer = FakeEvmSigner()
    signer_class.return_value = signer

    facilitator, configured_signer = build_configured_facilitator()

    assert configured_signer is signer
    assert signer_class.call_args.kwargs["chain_id"] == 84532
    assert [kind.network for kind in facilitator.get_supported().kinds] == ["eip155:84532"]


def test_official_base_exact_rejects_tampered_signature() -> None:
    signer = FakeEvmSigner()
    facilitator = build_facilitator(signer)
    payload, requirements = _payment()
    payload.payload["signature"] = "0x" + "11" * 64 + "1b"

    result = facilitator.verify(payload, requirements)

    assert result.is_valid is False
    assert result.invalid_reason == "invalid_exact_evm_payload_signature"
    assert signer.simulated_transfer is False


def test_durable_signer_persists_hash_before_broadcast() -> None:
    events: list[tuple[str, str]] = []
    built_transactions: list[dict] = []
    raw_transaction = b"signed-transaction"
    expected_hash = "0x" + __import__("web3").Web3.keccak(raw_transaction).hex().removeprefix("0x")

    class Function:
        def build_transaction(self, transaction):  # noqa: ANN001, ANN201
            built_transactions.append(transaction)
            return {**transaction, "data": "0x1234"}

    class Functions:
        def transferWithAuthorization(self, *args):  # noqa: ANN002, N802, ANN201
            return Function()

    class Contract:
        functions = Functions()

    class Eth:
        gas_price = 1

        def contract(self, address, abi):  # noqa: ANN001, ANN201
            return Contract()

        def send_raw_transaction(self, raw):  # noqa: ANN001, ANN201
            assert raw == raw_transaction
            assert events == [("prepared", expected_hash)]

            class Hash:
                def hex(self) -> str:
                    return expected_hash

            return Hash()

    class Account:
        address = "0x0000000000000000000000000000000000000001"

        def sign_transaction(self, transaction):  # noqa: ANN001, ANN201
            return type("Signed", (), {"raw_transaction": raw_transaction})()

    signer = object.__new__(DurableFacilitatorWeb3Signer)
    signer._w3 = type("Web3Client", (), {"eth": Eth()})()
    signer._account = Account()
    signer._gas_limit = 250000
    signer._chain_id = 8453
    signer._reserve_nonce = lambda: 7
    signer._on_transaction_prepared = lambda tx_hash, raw, nonce: events.append(("prepared", tx_hash))
    signer._on_transaction_broadcast = lambda tx_hash: events.append(("broadcast", tx_hash))

    result = signer.write_contract(
        USDC_BASE,
        [],
        "transferWithAuthorization",
        "arg",
    )

    assert result == expected_hash
    assert events == [("prepared", expected_hash), ("broadcast", expected_hash)]
    assert built_transactions[0]["chainId"] == 8453
