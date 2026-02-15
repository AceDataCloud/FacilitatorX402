"""
Base chain handler for EVM-based Base network.
"""

from typing import Any, Dict

from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from loguru import logger
from web3 import HTTPProvider, Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from .base import ChainHandler, SettlementResult, VerificationResult

# USDC transferWithAuthorization ABI
USDC_TRANSFER_WITH_AUTHORIZATION_ABI = [
    {
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "v", "type": "uint8"},
            {"name": "r", "type": "bytes32"},
            {"name": "s", "type": "bytes32"},
        ],
        "name": "transferWithAuthorization",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


class BaseChainHandler(ChainHandler):
    """Handler for Base (Ethereum L2) blockchain."""

    CHAIN_ID = 8453  # Base mainnet

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Support both new X402_BASE_* and legacy X402_* env via config
        from django.conf import settings

        self.rpc_url = config.get("rpc_url") or getattr(
            settings, "X402_BASE_RPC_URL", getattr(settings, "X402_RPC_URL", "")
        )
        self.signer_private_key = config.get("signer_private_key") or getattr(
            settings, "X402_BASE_SIGNER_PRIVATE_KEY", getattr(settings, "X402_SIGNER_PRIVATE_KEY", "")
        )
        self.signer_address = config.get("signer_address") or getattr(
            settings, "X402_BASE_SIGNER_ADDRESS", getattr(settings, "X402_SIGNER_ADDRESS", "")
        )
        self.gas_limit = config.get("gas_limit", 250000)
        self.tx_timeout_seconds = config.get("tx_timeout_seconds", 120)
        self.max_fee_per_gas_wei = config.get("max_fee_per_gas_wei", 0)
        self.max_priority_fee_per_gas_wei = config.get("max_priority_fee_per_gas_wei", 0)

    @property
    def chain_name(self) -> str:
        return "base"

    def validate_address(self, address: str) -> bool:
        """Validate Ethereum address format."""
        try:
            Web3.to_checksum_address(address)
            return True
        except (ValueError, TypeError):
            return False

    def _normalize_address(self, address: str) -> str:
        """Normalize to checksum address."""
        return Web3.to_checksum_address(address)

    def _signature_to_components(self, signature: str) -> tuple:
        """Split signature into v, r, s components."""
        sig_bytes = HexBytes(signature)
        if len(sig_bytes) != 65:
            raise ValueError("Signature must be 65 bytes")
        r = sig_bytes[:32]
        s = sig_bytes[32:64]
        v = sig_bytes[64]
        return v, r, s

    def verify_signature(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> VerificationResult:
        """
        Verify EIP-712 signature for USDC transferWithAuthorization.
        """
        try:
            authorization = payload.get("payload", {}).get("authorization", {})
            # Signature may be top-level (legacy) or inside payload
            signature = payload.get("signature") or payload.get("payload", {}).get("signature", "")
            extra = requirements.get("extra", {}) or {}

            required_fields = ["from", "to", "value", "validAfter", "validBefore", "nonce"]
            missing = [f for f in required_fields if not authorization.get(f)]
            if missing:
                return VerificationResult(
                    is_valid=False, invalid_reason=f"Missing authorization fields: {', '.join(missing)}"
                )

            if not signature:
                return VerificationResult(is_valid=False, invalid_reason="Missing authorization signature")

            try:
                payer = self._normalize_address(authorization.get("from", ""))
                pay_to = self._normalize_address(requirements.get("payTo", ""))
                auth_to = self._normalize_address(authorization.get("to", ""))
            except Exception as exc:
                return VerificationResult(is_valid=False, invalid_reason=f"Invalid address in payload: {exc}")

            if pay_to != auth_to:
                return VerificationResult(
                    is_valid=False, invalid_reason=f"Recipient mismatch: expected {pay_to}, got {auth_to}"
                )

            try:
                max_amount = int(requirements.get("maxAmountRequired", "0"))
                auth_value = int(authorization.get("value", "0"))
            except (TypeError, ValueError):
                return VerificationResult(is_valid=False, invalid_reason="Invalid amount in payload or requirements")

            if auth_value > max_amount:
                return VerificationResult(
                    is_valid=False, invalid_reason=f"Amount exceeds limit: {auth_value} > {max_amount}"
                )

            domain_name = extra.get("name") or extra.get("domain", {}).get("name")
            domain_version = extra.get("version") or extra.get("domain", {}).get("version")
            verifying_contract = (
                extra.get("verifyingContract")
                or extra.get("domain", {}).get("verifyingContract")
                or requirements.get("asset", "")
            )
            chain_id = extra.get("chainId") or extra.get("domain", {}).get("chainId") or self.CHAIN_ID

            if not domain_name or not domain_version:
                return VerificationResult(is_valid=False, invalid_reason="Missing token domain metadata")
            if not verifying_contract:
                return VerificationResult(is_valid=False, invalid_reason="Missing token contract address")

            try:
                nonce_bytes = HexBytes(authorization["nonce"])
                if len(nonce_bytes) != 32:
                    raise ValueError("Nonce must be 32 bytes")
            except Exception as exc:
                return VerificationResult(is_valid=False, invalid_reason=f"Invalid authorization nonce: {exc}")

            try:
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
                        "name": domain_name,
                        "version": domain_version,
                        "chainId": int(chain_id),
                        "verifyingContract": self._normalize_address(verifying_contract),
                    },
                    "message": {
                        "from": payer,
                        "to": auth_to,
                        "value": int(authorization["value"]),
                        "validAfter": int(authorization["validAfter"]),
                        "validBefore": int(authorization["validBefore"]),
                        "nonce": nonce_bytes,
                    },
                }
            except Exception as exc:
                return VerificationResult(is_valid=False, invalid_reason=f"Unable to build typed data: {exc}")

            try:
                signable_message = encode_typed_data(full_message=typed_data)
                recovered_address = Web3().eth.account.recover_message(signable_message, signature=signature)
                recovered = self._normalize_address(recovered_address)
            except Exception as exc:
                return VerificationResult(is_valid=False, invalid_reason=f"Verification error: {exc}")

            if payer != recovered:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f"Signature mismatch: expected {payer}, got {recovered}",
                    payer=recovered,
                )

            return VerificationResult(
                is_valid=True,
                payer=payer,
                details={
                    "amount": auth_value,
                    "nonce": authorization.get("nonce"),
                },
            )

        except Exception as e:
            logger.error(f"Base chain verification error: {e}")
            return VerificationResult(is_valid=False, invalid_reason=f"Verification error: {str(e)}")

    def settle_payment(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> SettlementResult:
        """
        Execute USDC transferWithAuthorization on Base chain.
        """
        try:
            # Get configuration
            rpc_url = self.config.get("rpc_url", "")
            private_key = self.config.get("signer_private_key", "")
            gas_limit = self.config.get("gas_limit", 250000)
            timeout = self.config.get("tx_timeout_seconds", 120)

            if not rpc_url:
                return SettlementResult(success=False, error_reason="RPC URL not configured")

            if not private_key:
                return SettlementResult(success=False, error_reason="Signer private key not configured")

            # Connect to Base chain
            web3 = Web3(HTTPProvider(rpc_url))
            if not web3.is_connected():
                return SettlementResult(success=False, error_reason="Unable to connect to RPC endpoint")

            # Prepare transaction
            account = web3.eth.account.from_key(private_key)
            signer_address = self._normalize_address(account.address)

            authorization = payload.get("payload", {}).get("authorization", {})
            # Signature may be top-level or nested under payload
            signature = payload.get("signature") or payload.get("payload", {}).get("signature", "")
            asset_address = self._normalize_address(requirements.get("asset", ""))

            # Get USDC contract
            contract = web3.eth.contract(
                address=asset_address,
                abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
            )

            # Prepare parameters
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
                logger.error(f"Settlement simulation failed: {error_msg}")
                return SettlementResult(success=False, error_reason=error_msg)
            except BadFunctionCallOutput:
                # Some USDC implementations don't return bool, continue anyway
                logger.warning("Settlement simulation returned empty data, continuing")

            # Estimate gas
            try:
                estimated_gas = transfer_fn.estimate_gas({"from": signer_address})
            except Exception:
                estimated_gas = gas_limit

            # Build transaction
            tx_params = {
                "chainId": self.CHAIN_ID,
                "from": signer_address,
                "nonce": web3.eth.get_transaction_count(signer_address),
                "gas": max(estimated_gas, gas_limit),
                "gasPrice": web3.eth.gas_price,
            }

            transaction = transfer_fn.build_transaction(tx_params)
            signed = web3.eth.account.sign_transaction(transaction, private_key=private_key)

            # Handle raw transaction attribute name across web3 versions
            raw_tx = getattr(signed, "rawTransaction", None)
            if raw_tx is None:
                raw_tx = getattr(signed, "raw_transaction", None)
            if raw_tx is None:
                return SettlementResult(success=False, error_reason="Signer returned unexpected transaction encoding")

            # Send transaction
            tx_hash = web3.eth.send_raw_transaction(raw_tx)
            tx_hash_hex = tx_hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex
            logger.info(f"Settlement transaction submitted: {tx_hash_hex}")

            # Wait for confirmation
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)

            if receipt.status != 1:
                failed_tx_hash = tx_hash.hex()
                if not failed_tx_hash.startswith("0x"):
                    failed_tx_hash = "0x" + failed_tx_hash
                return SettlementResult(
                    success=False, transaction_hash=failed_tx_hash, error_reason="Transaction reverted on-chain"
                )

            # Ensure tx_hash has 0x prefix
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
            logger.error(f"Base chain settlement error: {e}")
            return SettlementResult(success=False, error_reason=f"Settlement error: {str(e)}")

    def _map_contract_error(self, exc: ContractLogicError) -> str:
        """Map contract errors to user-friendly messages."""
        message = str(exc).lower()
        if "amount exceeds balance" in message or "insufficient balance" in message:
            return "Payer has insufficient USDC balance"
        if "insufficient funds" in message:
            return "Facilitator has insufficient ETH for gas"
        return "Settlement transaction reverted on-chain"

    def get_explorer_url(self, tx_hash: str) -> str:
        """Get BaseScan explorer URL."""
        return f"https://basescan.org/tx/{tx_hash}"
