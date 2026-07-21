import base64
from collections.abc import Callable

from hexbytes import HexBytes
from solders.signature import Signature
from solders.transaction import VersionedTransaction
from solders.transaction_status import TransactionConfirmationStatus
from web3 import Web3
from web3.exceptions import TransactionNotFound
from x402.mechanisms.evm.data_suffix import append_data_suffix
from x402.mechanisms.evm.signer import TransactionReceipt
from x402.mechanisms.evm.signers import FacilitatorWeb3Signer
from x402.mechanisms.svm.signers import FacilitatorKeypairSigner


class DurableFacilitatorWeb3Signer(FacilitatorWeb3Signer):
    def __init__(
        self,
        private_key: str,
        rpc_url: str,
        gas_limit: int,
        receipt_timeout: int,
        chain_id: int,
        on_transaction_prepared: Callable[[str, str, int], None] | None = None,
        on_transaction_broadcast: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(private_key=private_key, rpc_url=rpc_url)
        self._gas_limit = gas_limit
        self._receipt_timeout = receipt_timeout
        self._chain_id = chain_id
        self._on_transaction_prepared = on_transaction_prepared
        self._on_transaction_broadcast = on_transaction_broadcast
        if self._w3.eth.chain_id != self._chain_id:
            raise RuntimeError(f"Base RPC chain ID mismatch: expected {self._chain_id}")

    def write_contract(
        self,
        address: str,
        abi: list[dict],
        function_name: str,
        *args,
        data_suffix: str | None = None,
    ) -> str:
        contract = self._w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
        function = getattr(contract.functions, function_name)(*args)
        transaction = function.build_transaction(
            {
                "from": self._account.address,
                "nonce": self._reserve_nonce(),
                "gas": self._gas_limit,
                "gasPrice": self._w3.eth.gas_price,
                "chainId": self._chain_id,
            }
        )
        if data_suffix:
            calldata = transaction["data"]
            if isinstance(calldata, (bytes, bytearray)):
                calldata = "0x" + bytes(calldata).hex()
            transaction["data"] = append_data_suffix(calldata, data_suffix)

        signed = self._account.sign_transaction(transaction)
        raw_transaction = signed.raw_transaction
        prepared_hash = Web3.keccak(raw_transaction).hex()
        if not prepared_hash.startswith("0x"):
            prepared_hash = "0x" + prepared_hash
        if self._on_transaction_prepared:
            self._on_transaction_prepared(prepared_hash, raw_transaction.hex(), transaction["nonce"])

        submitted_hash = self._w3.eth.send_raw_transaction(raw_transaction).hex()
        if not submitted_hash.startswith("0x"):
            submitted_hash = "0x" + submitted_hash
        if submitted_hash.lower() != prepared_hash.lower():
            raise RuntimeError("RPC returned a different settlement transaction hash")
        if self._on_transaction_broadcast:
            self._on_transaction_broadcast(submitted_hash)
        return submitted_hash

    def broadcast_prepared(self, raw_transaction_hex: str) -> str:
        raw_transaction = HexBytes(raw_transaction_hex)
        prepared_hash = Web3.keccak(raw_transaction).hex()
        if not prepared_hash.startswith("0x"):
            prepared_hash = "0x" + prepared_hash
        submitted_hash = self._w3.eth.send_raw_transaction(raw_transaction).hex()
        if not submitted_hash.startswith("0x"):
            submitted_hash = "0x" + submitted_hash
        if submitted_hash.lower() != prepared_hash.lower():
            raise RuntimeError("RPC returned a different settlement transaction hash")
        if self._on_transaction_broadcast:
            self._on_transaction_broadcast(submitted_hash)
        return submitted_hash

    def wait_for_transaction_receipt(self, tx_hash: str) -> TransactionReceipt:
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self._receipt_timeout)
        return TransactionReceipt(
            status=1 if receipt["status"] == 1 else 0,
            block_number=receipt["blockNumber"],
            tx_hash=tx_hash,
        )

    def get_transaction_status(self, tx_hash: str) -> str:
        try:
            receipt = self._w3.eth.get_transaction_receipt(tx_hash)
        except TransactionNotFound:
            return "pending"
        return "confirmed" if receipt["status"] == 1 else "failed"


class DurableFacilitatorSvmSigner(FacilitatorKeypairSigner):
    def __init__(
        self,
        private_key: str,
        rpc_url: str,
        on_transaction_prepared: Callable[[str, str, int | None], None] | None = None,
        on_transaction_broadcast: Callable[[str], None] | None = None,
    ) -> None:
        signer = FacilitatorKeypairSigner.from_base58(private_key, rpc_url)
        super().__init__(list(signer._keypairs.values()), rpc_url)
        self._on_transaction_prepared = on_transaction_prepared
        self._on_transaction_broadcast = on_transaction_broadcast

    @staticmethod
    def transaction_signature(tx_base64: str) -> str:
        transaction = VersionedTransaction.from_bytes(base64.b64decode(tx_base64))
        signature = str(transaction.signatures[0])
        if signature == str(Signature.default()):
            raise RuntimeError("SVM facilitator transaction has no fee payer signature")
        return signature

    def sign_transaction(self, tx_base64: str, fee_payer: str, network: str) -> str:
        return super().sign_transaction(tx_base64, fee_payer, network)

    def send_transaction(self, tx_base64: str, network: str) -> str:
        expected = self.transaction_signature(tx_base64)
        if self._on_transaction_prepared:
            self._on_transaction_prepared(expected, tx_base64, None)
        submitted = super().send_transaction(tx_base64, network)
        if submitted != expected:
            raise RuntimeError("RPC returned a different SVM settlement signature")
        if self._on_transaction_broadcast:
            self._on_transaction_broadcast(submitted)
        return submitted

    def broadcast_prepared(self, tx_base64: str, network: str) -> str:
        return self.send_transaction(tx_base64, network)

    def get_transaction_status(self, signature: str, network: str) -> str:
        result = self._get_client(network).get_signature_statuses([Signature.from_string(signature)])
        if not result.value or result.value[0] is None:
            return "pending"
        status = result.value[0]
        if status.err:
            return "failed"
        return (
            "confirmed"
            if status.confirmation_status == TransactionConfirmationStatus.Confirmed
            or status.confirmation_status == TransactionConfirmationStatus.Finalized
            else "pending"
        )
