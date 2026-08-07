import base64

import pytest
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.null_signer import NullSigner
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from x402.mechanisms.svm.constants import (
    ERR_INVALID_COMPUTE_LIMIT,
    ERR_INVALID_COMPUTE_PRICE,
    LIGHTHOUSE_PROGRAM_ADDRESS,
    MEMO_PROGRAM_ADDRESS,
    SOLANA_MAINNET_CAIP2,
    TOKEN_PROGRAM_ADDRESS,
)
from x402.mechanisms.svm.utils import derive_ata
from x402.schemas import PaymentPayload, PaymentRequirements

from x402f.svm_exact import (
    ERR_AMOUNT_MISMATCH,
    ERR_COMPUTE_INSTRUCTION_COUNT,
    ERR_DUPLICATE_TRANSFER,
    ERR_FEE_PAYER_ACCOUNT_MISMATCH,
    ERR_FEE_PAYER_IN_INSTRUCTION,
    ERR_SIGNER_SET_MISMATCH,
    OutcomeExactSvmFacilitatorScheme,
)

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PAY_TO = "5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43"


class FakeSigner:
    def __init__(self, fee_payer: Keypair) -> None:
        self.fee_payer = fee_payer
        self.simulated = False

    def get_addresses(self) -> list[str]:
        return [str(self.fee_payer.pubkey())]

    def sign_transaction(self, transaction: str, fee_payer: str, network: str) -> str:
        assert fee_payer == str(self.fee_payer.pubkey())
        assert network == SOLANA_MAINNET_CAIP2
        return transaction

    def simulate_transaction(self, transaction: str, network: str) -> None:
        assert transaction
        assert network == SOLANA_MAINNET_CAIP2
        self.simulated = True


def lighthouse(payer: Pubkey, discriminator: int = 6) -> Instruction:
    return Instruction(
        Pubkey.from_string(LIGHTHOUSE_PROGRAM_ADDRESS),
        bytes([discriminator]) + b"lighthouse",
        [AccountMeta(payer, is_signer=False, is_writable=False)],
    )


def memo(value: bytes = b"0123456789abcdef0123456789abcdef") -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM_ADDRESS), value, [])


def payment(
    *,
    extras_before: list[Instruction] | None = None,
    extras_after: list[Instruction] | None = None,
    authority: Keypair | None = None,
    fee_payer: Keypair | None = None,
    additional_signers: list[Keypair] | None = None,
    duplicate_transfer: bool = False,
    extra_compute_limit: bool = False,
    compute_limit: int = 100_000,
    compute_price: int = 5_000,
    transfer_amount: int = 100_000,
) -> tuple[PaymentPayload, PaymentRequirements, FakeSigner]:
    sponsor = fee_payer or Keypair()
    payer = authority or Keypair()
    signer = FakeSigner(sponsor)
    token_program = Pubkey.from_string(TOKEN_PROGRAM_ADDRESS)
    mint = Pubkey.from_string(USDC)
    source = Pubkey.from_string(derive_ata(str(payer.pubkey()), USDC, TOKEN_PROGRAM_ADDRESS))
    destination = Pubkey.from_string(derive_ata(PAY_TO, USDC, TOKEN_PROGRAM_ADDRESS))
    transfer = Instruction(
        token_program,
        bytes([12]) + transfer_amount.to_bytes(8, "little") + bytes([6]),
        [
            AccountMeta(source, is_signer=False, is_writable=True),
            AccountMeta(mint, is_signer=False, is_writable=False),
            AccountMeta(destination, is_signer=False, is_writable=True),
            AccountMeta(payer.pubkey(), is_signer=True, is_writable=False),
        ],
    )
    instructions = [
        set_compute_unit_limit(compute_limit),
        set_compute_unit_price(compute_price),
        *([set_compute_unit_limit(compute_limit)] if extra_compute_limit else []),
        *(extras_before or []),
        transfer,
    ]
    if duplicate_transfer:
        instructions.append(transfer)
    instructions.extend(extras_after or [])
    message = MessageV0.try_compile(sponsor.pubkey(), instructions, [], Hash.default())
    signers = [NullSigner(sponsor.pubkey())]
    if sponsor.pubkey() != payer.pubkey():
        signers.append(payer)
    signers.extend(additional_signers or [])
    transaction = VersionedTransaction(message, signers)
    requirements = PaymentRequirements.model_validate(
        {
            "scheme": "exact",
            "network": SOLANA_MAINNET_CAIP2,
            "asset": USDC,
            "amount": "100000",
            "payTo": PAY_TO,
            "maxTimeoutSeconds": 120,
            "extra": {
                "feePayer": str(sponsor.pubkey()),
                "computeUnitLimit": 100_000,
                "computeUnitPriceMicroLamports": 5_000,
            },
        }
    )
    payload = PaymentPayload.model_validate(
        {
            "x402Version": 2,
            "accepted": requirements.model_dump(by_alias=True),
            "payload": {"transaction": base64.b64encode(bytes(transaction)).decode()},
        }
    )
    return payload, requirements, signer


def verify(payload, requirements, signer):
    return OutcomeExactSvmFacilitatorScheme(signer).verify(payload, requirements)


def test_accepts_observed_phantom_eight_instruction_layout() -> None:
    payer = Keypair()
    payload, requirements, signer = payment(
        authority=payer,
        extras_before=[lighthouse(payer.pubkey(), 10), lighthouse(payer.pubkey()), lighthouse(payer.pubkey())],
        extras_after=[memo(), lighthouse(payer.pubkey(), 10)],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is True
    assert result.payer == str(payer.pubkey())
    assert signer.simulated is True


def test_accepts_phantom_lighthouse_reference_to_sponsored_fee_payer() -> None:
    sponsor = Keypair()
    payer = Keypair()
    payload, requirements, signer = payment(
        authority=payer,
        fee_payer=sponsor,
        extras_before=[lighthouse(sponsor.pubkey())],
        extras_after=[memo()],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is True
    assert result.payer == str(payer.pubkey())
    assert signer.simulated is True


def test_accepts_wallet_instruction_without_positional_assumptions() -> None:
    payer = Keypair()
    wallet_instruction = Instruction(
        Pubkey.new_unique(),
        b"wallet-safety-check",
        [AccountMeta(payer.pubkey(), is_signer=False, is_writable=False)],
    )
    payload, requirements, signer = payment(
        authority=payer,
        extras_before=[wallet_instruction],
        extras_after=[memo()],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is True
    assert signer.simulated is True


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"duplicate_transfer": True}, ERR_DUPLICATE_TRANSFER),
        ({"extra_compute_limit": True}, ERR_COMPUTE_INSTRUCTION_COUNT),
        ({"compute_limit": 100_001}, ERR_INVALID_COMPUTE_LIMIT),
        ({"compute_price": 5_001}, ERR_INVALID_COMPUTE_PRICE),
        ({"transfer_amount": 100_001}, ERR_AMOUNT_MISMATCH),
    ],
)
def test_rejects_payment_or_fee_policy_violations(kwargs, reason) -> None:
    payload, requirements, signer = payment(extras_after=[memo()], **kwargs)

    result = verify(payload, requirements, signer)

    assert result.is_valid is False
    assert result.invalid_reason == reason
    assert signer.simulated is False


def test_rejects_any_instruction_that_references_fee_payer() -> None:
    sponsor = Keypair()
    unsafe = Instruction(
        Pubkey.new_unique(),
        b"unsafe",
        [AccountMeta(sponsor.pubkey(), is_signer=False, is_writable=False)],
    )
    payload, requirements, signer = payment(
        fee_payer=sponsor,
        extras_before=[unsafe],
        extras_after=[memo()],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_FEE_PAYER_IN_INSTRUCTION
    assert signer.simulated is False


def test_rejects_additional_required_signer() -> None:
    extra_signer = Keypair()
    instruction = Instruction(
        Pubkey.new_unique(),
        b"extra-signer",
        [AccountMeta(extra_signer.pubkey(), is_signer=True, is_writable=False)],
    )
    payload, requirements, signer = payment(
        extras_before=[instruction],
        extras_after=[memo()],
        additional_signers=[extra_signer],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_SIGNER_SET_MISMATCH
    assert signer.simulated is False


def test_rejects_transaction_fee_payer_mismatch() -> None:
    payload, requirements, signer = payment(extras_after=[memo()])
    replacement = Keypair()
    signer.fee_payer = replacement
    requirements.extra["feePayer"] = str(replacement.pubkey())
    payload.accepted.extra["feePayer"] = str(replacement.pubkey())

    result = verify(payload, requirements, signer)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_FEE_PAYER_ACCOUNT_MISMATCH
    assert signer.simulated is False


def test_rejects_facilitator_as_transfer_authority() -> None:
    fee_payer = Keypair()
    payload, requirements, signer = payment(
        authority=fee_payer,
        fee_payer=fee_payer,
        extras_after=[memo()],
    )

    result = verify(payload, requirements, signer)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_SIGNER_SET_MISMATCH
    assert signer.simulated is False
