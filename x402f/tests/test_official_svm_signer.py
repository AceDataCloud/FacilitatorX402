import base64
from types import SimpleNamespace
from unittest.mock import Mock, patch

from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.transaction import VersionedTransaction
from solders.transaction_status import TransactionConfirmationStatus

from x402f.official_signer import DurableFacilitatorSvmSigner


def unsigned_transaction(fee_payer: Keypair) -> str:
    message = Message.new_with_blockhash([], fee_payer.pubkey(), Hash.default())
    transaction = VersionedTransaction(message, [fee_payer])
    transaction.signatures[0] = __import__("solders.signature").signature.Signature.default()
    return base64.b64encode(bytes(transaction)).decode()


def test_durable_svm_signer_persists_before_broadcast_and_replays_identically() -> None:
    fee_payer = Keypair()
    prepared = Mock()
    broadcast = Mock()
    signer = DurableFacilitatorSvmSigner(
        str(fee_payer),
        "https://solana.test",
        on_transaction_prepared=prepared,
        on_transaction_broadcast=broadcast,
    )
    signed = signer.sign_transaction(unsigned_transaction(fee_payer), str(fee_payer.pubkey()), "solana:test")
    signer.sign_transaction(unsigned_transaction(fee_payer), str(fee_payer.pubkey()), "solana:test")
    expected = signer.transaction_signature(signed)

    prepared.assert_not_called()
    with patch.object(DurableFacilitatorSvmSigner.__mro__[1], "send_transaction", return_value=expected):
        assert signer.broadcast_prepared(signed, "solana:test") == expected
    prepared.assert_called_once_with(expected, signed, None)
    broadcast.assert_called_once_with(expected)


def test_svm_status_requires_confirmed_or_finalized() -> None:
    signer = object.__new__(DurableFacilitatorSvmSigner)
    client = Mock()
    signer._get_client = Mock(return_value=client)
    signature = str(__import__("solders.signature").signature.Signature.new_unique())

    for confirmation, expected in (
        (TransactionConfirmationStatus.Processed, "pending"),
        (TransactionConfirmationStatus.Confirmed, "confirmed"),
        (TransactionConfirmationStatus.Finalized, "confirmed"),
    ):
        client.get_signature_statuses.return_value = SimpleNamespace(
            value=[SimpleNamespace(err=None, confirmation_status=confirmation)]
        )
        assert signer.get_transaction_status(signature, "solana:test") == expected
