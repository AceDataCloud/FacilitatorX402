from collections.abc import Callable

from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TransactionNotFound
from x402.mechanisms.evm.data_suffix import append_data_suffix
from x402.mechanisms.evm.signer import TransactionReceipt
from x402.mechanisms.evm.signers import FacilitatorWeb3Signer


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
