"""
SKALE Base chain handler for EVM-based SKALE network.

SKALE Base is a zero-gas-fee EVM-compatible chain that bridges assets from Base.
It uses the same EIP-712 TransferWithAuthorization flow as Base, but with:
- Different Chain ID (1187947933 for mainnet)
- Zero gas fees (transactions cost nothing)
- Different RPC endpoint and USDC.e contract address
"""

from typing import Any, Dict

from loguru import logger
from web3 import HTTPProvider, Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from .base import SettlementResult
from .base_chain import BaseChainHandler


class SkaleChainHandler(BaseChainHandler):
    """
    Handler for SKALE Base blockchain (zero gas fees, EVM-compatible).

    Inherits all EIP-712 verification logic from BaseChainHandler.
    Overrides settlement to handle zero-gas transactions and SKALE-specific config.
    """

    CHAIN_ID = 1187947933  # SKALE Base mainnet

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        from django.conf import settings

        self.rpc_url = config.get("rpc_url") or getattr(settings, "X402_SKALE_RPC_URL", "")
        self.signer_private_key = config.get("signer_private_key") or getattr(
            settings, "X402_SKALE_SIGNER_PRIVATE_KEY", ""
        )
        self.signer_address = config.get("signer_address") or getattr(settings, "X402_SKALE_SIGNER_ADDRESS", "")

    @property
    def chain_name(self) -> str:
        return "skale"

    def settle_payment(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> SettlementResult:
        """
        Execute USDC.e transferWithAuthorization on SKALE Base chain.

        SKALE has zero gas fees, so we set gasPrice=0 and use a minimal gas limit.
        """
        try:
            from .base_chain import USDC_TRANSFER_WITH_AUTHORIZATION_ABI

            rpc_url = self.config.get("rpc_url", "")
            private_key = self.config.get("signer_private_key", "")
            timeout = self.config.get("tx_timeout_seconds", 120)

            if not rpc_url:
                return SettlementResult(success=False, error_reason="SKALE RPC URL not configured")
            if not private_key:
                return SettlementResult(success=False, error_reason="SKALE signer private key not configured")

            web3 = Web3(HTTPProvider(rpc_url))
            if not web3.is_connected():
                return SettlementResult(success=False, error_reason="Unable to connect to SKALE RPC endpoint")

            account = web3.eth.account.from_key(private_key)
            signer_address = self._normalize_address(account.address)

            authorization = payload.get("payload", {}).get("authorization", {})
            signature = payload.get("signature") or payload.get("payload", {}).get("signature", "")
            asset_address = self._normalize_address(requirements.get("asset", ""))

            from hexbytes import HexBytes

            contract = web3.eth.contract(
                address=asset_address,
                abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
            )

            nonce_bytes = HexBytes(authorization["nonce"])
            v, r, s = self._signature_to_components(signature)

            transfer_fn = contract.functions.transferWithAuthorization(
                self._normalize_address(authorization["from"]),
                self._normalize_address(authorization["to"]),
                int(authorization["value"]),
                int(authorization["validAfter"]),
                int(authorization["validBefore"]),
                nonce_bytes,
                v,
                r,
                s,
            )

            # Pre-flight simulation
            try:
                transfer_fn.call({"from": signer_address})
            except ContractLogicError as exc:
                error_msg = self._map_contract_error(exc)
                logger.error(f"SKALE settlement simulation failed: {error_msg}")
                return SettlementResult(success=False, error_reason=error_msg)
            except BadFunctionCallOutput:
                logger.warning("SKALE settlement simulation returned empty data, continuing")

            # Estimate gas (SKALE still uses gas for EVM compatibility, but it's free)
            try:
                estimated_gas = transfer_fn.estimate_gas({"from": signer_address})
            except Exception:
                estimated_gas = 250000

            # Build transaction — SKALE has zero gas fees
            tx_params = {
                "chainId": self.CHAIN_ID,
                "from": signer_address,
                "nonce": web3.eth.get_transaction_count(signer_address),
                "gas": estimated_gas,
                "gasPrice": web3.eth.gas_price,  # On SKALE this returns 0 or minimal value
            }

            transaction = transfer_fn.build_transaction(tx_params)
            signed = web3.eth.account.sign_transaction(transaction, private_key=private_key)

            raw_tx = getattr(signed, "rawTransaction", None)
            if raw_tx is None:
                raw_tx = getattr(signed, "raw_transaction", None)
            if raw_tx is None:
                return SettlementResult(success=False, error_reason="Signer returned unexpected transaction encoding")

            tx_hash = web3.eth.send_raw_transaction(raw_tx)
            tx_hash_hex = tx_hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex
            logger.info(f"SKALE settlement transaction submitted: {tx_hash_hex}")

            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)

            if receipt.status != 1:
                failed_tx_hash = tx_hash.hex()
                if not failed_tx_hash.startswith("0x"):
                    failed_tx_hash = "0x" + failed_tx_hash
                return SettlementResult(
                    success=False, transaction_hash=failed_tx_hash, error_reason="Transaction reverted on SKALE chain"
                )

            tx_hash_hex = tx_hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex

            return SettlementResult(
                success=True,
                transaction_hash=tx_hash_hex,
                payer=self._normalize_address(authorization["from"]),
                details={
                    "block": receipt.blockNumber,
                    "gas_used": receipt.gasUsed,
                },
            )

        except Exception as e:
            logger.error(f"SKALE chain settlement error: {e}")
            return SettlementResult(success=False, error_reason=f"Settlement error: {str(e)}")

    def get_explorer_url(self, tx_hash: str) -> str:
        """Get SKALE Base explorer URL."""
        return f"https://skale-base-explorer.skalenodes.com/tx/{tx_hash}"
