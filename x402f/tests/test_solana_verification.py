import base64
from types import SimpleNamespace

import base58
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.null_signer import NullSigner
from solders.signature import Signature
from solders.transaction import VersionedTransaction
from spl.token.instructions import get_associated_token_address

from x402f.chain_handlers.solana_exact import (
    COMPUTE_BUDGET_PROGRAM_ID,
    MEMO_PROGRAM_ID_V1,
    TOKEN_PROGRAM_ID,
    SolanaExactHandler,
)
from x402f.views_multichain import _extract_nonce


def test_preflight_rejection_is_marked_as_not_broadcast():
    code, details = SolanaExactHandler._normalize_send_transaction_error(
        Exception("Transaction simulation failed: Blockhash not found")
    )

    assert code == "SEND_TRANSACTION_FAILED"
    assert details["broadcast_status"] == "rejected"


def test_transport_error_remains_ambiguous():
    code, details = SolanaExactHandler._normalize_send_transaction_error(Exception("connection reset by peer"))

    assert code == "SEND_TRANSACTION_FAILED"
    assert "broadcast_status" not in details


USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
AMOUNT = 952


def _payment(
    payer_signer,
    *,
    compute_limit=100_000,
    compute_price=5_000,
    include_memo=True,
    first_compute_instruction=None,
):
    fee_payer = Keypair.from_seed(bytes(range(32)))
    payer = Keypair.from_seed(bytes(range(1, 33)))
    pay_to = Keypair.from_seed(bytes(range(2, 34))).pubkey()
    mint = Keypair.from_seed(bytes(range(3, 35))).pubkey()
    source = get_associated_token_address(payer.pubkey(), mint)
    destination = get_associated_token_address(pay_to, mint)
    transfer = Instruction(
        program_id=TOKEN_PROGRAM_ID,
        accounts=[
            AccountMeta(source, False, True),
            AccountMeta(mint, False, False),
            AccountMeta(destination, False, True),
            AccountMeta(payer.pubkey(), True, False),
        ],
        data=bytes([12]) + AMOUNT.to_bytes(8, "little") + bytes([6]),
    )
    instructions = [
        first_compute_instruction or set_compute_unit_limit(compute_limit),
        set_compute_unit_price(compute_price),
        transfer,
    ]
    if include_memo:
        instructions.append(Instruction(MEMO_PROGRAM_ID_V1, b"00" * 16, []))
    message = MessageV0.try_compile(
        fee_payer.pubkey(),
        instructions,
        [],
        Hash.default(),
    )
    transaction = VersionedTransaction(
        message,
        [NullSigner(fee_payer.pubkey()), payer_signer(payer)],
    )
    payload = {
        "x402Version": 2,
        "scheme": "exact",
        "network": "solana",
        "payload": {"transaction": base64.b64encode(bytes(transaction)).decode("ascii")},
    }
    requirements = {
        "scheme": "exact",
        "network": "solana",
        "amount": str(AMOUNT),
        "payTo": str(pay_to),
        "asset": str(mint),
        "extra": {"feePayer": str(fee_payer.pubkey())},
    }
    handler = SolanaExactHandler(
        {
            "signer_address": str(fee_payer.pubkey()),
            "signer_private_key": base58.b58encode(bytes(fee_payer)).decode("ascii"),
        }
    )
    return handler, payload, requirements, transaction


def test_verify_rejects_missing_payer_signature():
    handler, payload, requirements, _ = _payment(lambda payer: NullSigner(payer.pubkey()))

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "Missing or invalid payer signature"


def test_verify_rejects_prefilled_fee_payer_signature():
    handler, payload, requirements, transaction = _payment(lambda payer: payer)
    signatures = list(transaction.signatures)
    signatures[0] = Keypair().sign_message(b"not the transaction")
    transaction = VersionedTransaction.populate(transaction.message, signatures)
    payload["payload"]["transaction"] = base64.b64encode(bytes(transaction)).decode("ascii")

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "Fee payer signature must be empty"


def test_verify_accepts_valid_partial_signatures():
    handler, payload, requirements, _ = _payment(lambda payer: payer)

    result = handler.verify_signature(payload, requirements)

    assert result.is_valid, result.invalid_reason
    assert result.details["nonce"].startswith("solana:")
    assert _extract_nonce(payload, "solana") == result.details["nonce"]


def test_verify_rejects_unsubmitted_wallet_fee_payer_transaction():
    _, payload, requirements, _ = _payment(lambda payer: payer)
    handler = SolanaExactHandler({"signer_address": str(Keypair().pubkey())})

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "Fee payer does not match facilitator configuration"


def test_settle_revalidates_before_signing():
    handler, payload, requirements, _ = _payment(lambda payer: NullSigner(payer.pubkey()))

    result = handler.settle_payment(payload, requirements)

    assert not result.success
    assert result.error_reason == "Missing or invalid payer signature"


def test_settle_fails_when_confirmation_times_out(monkeypatch):
    handler, payload, requirements, _ = _payment(lambda payer: payer)
    transaction_signature = Signature.from_bytes(bytes(range(64)))

    class RpcClient:
        def send_raw_transaction(self, *_args, **_kwargs):
            return SimpleNamespace(value=transaction_signature)

        def confirm_transaction(self, *_args, **_kwargs):
            raise RuntimeError("confirmation timed out")

    monkeypatch.setattr("x402f.chain_handlers.solana_exact.Client", lambda _url: RpcClient())

    result = handler.settle_payment(payload, requirements)

    assert not result.success
    assert result.transaction_hash == str(transaction_signature)
    assert result.error_reason == "Transaction confirmation failed: confirmation timed out"


def test_reconcile_rejects_processed_transaction(monkeypatch):
    handler, _, _, _ = _payment(lambda payer: payer)

    class RpcClient:
        def get_signature_statuses(self, _signatures):
            return SimpleNamespace(value=[SimpleNamespace(err=None, confirmation_status="processed")])

    monkeypatch.setattr("x402f.chain_handlers.solana_exact.Client", lambda _url: RpcClient())

    assert handler.check_transaction_status(str(Signature.default())) is False


def test_reconcile_accepts_confirmed_transaction(monkeypatch):
    handler, _, _, _ = _payment(lambda payer: payer)

    class RpcClient:
        def get_signature_statuses(self, _signatures):
            return SimpleNamespace(value=[SimpleNamespace(err=None, confirmation_status="confirmed")])

    monkeypatch.setattr("x402f.chain_handlers.solana_exact.Client", lambda _url: RpcClient())

    assert handler.check_transaction_status(str(Signature.default())) is True


def test_verify_rejects_missing_memo_nonce():
    handler, payload, requirements, _ = _payment(lambda payer: payer, include_memo=False)

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "Exactly one payment memo is required"


def test_verify_rejects_excessive_compute_unit_limit():
    handler, payload, requirements, _ = _payment(lambda payer: payer, compute_limit=500_000)

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "Compute unit limit 500000 exceeds maximum 400000"


def test_verify_rejects_wrong_compute_budget_discriminator():
    request_heap_frame = Instruction(
        COMPUTE_BUDGET_PROGRAM_ID,
        bytes([1]) + (32_768).to_bytes(4, "little"),
        [],
    )
    handler, payload, requirements, _ = _payment(
        lambda payer: payer,
        first_compute_instruction=request_heap_frame,
    )

    result = handler.verify_signature(payload, requirements)

    assert not result.is_valid
    assert result.invalid_reason == "First instruction must be ComputeBudget SetComputeUnitLimit"
