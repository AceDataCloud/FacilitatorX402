"""
Base chain handler for EVM-based Base network.
"""
from typing import Dict, Any
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError, BadFunctionCallOutput
from eth_account.messages import encode_structured_data
from hexbytes import HexBytes
from loguru import logger

from .base import ChainHandler, VerificationResult, SettlementResult


# USDC transferWithAuthorization ABI
USDC_TRANSFER_WITH_AUTHORIZATION_ABI = [
    {
        'inputs': [
            {'name': 'from', 'type': 'address'},
            {'name': 'to', 'type': 'address'},
            {'name': 'value', 'type': 'uint256'},
            {'name': 'validAfter', 'type': 'uint256'},
            {'name': 'validBefore', 'type': 'uint256'},
            {'name': 'nonce', 'type': 'bytes32'},
            {'name': 'v', 'type': 'uint8'},
            {'name': 'r', 'type': 'bytes32'},
            {'name': 's', 'type': 'bytes32'},
        ],
        'name': 'transferWithAuthorization',
        'outputs': [],
        'stateMutability': 'nonpayable',
        'type': 'function',
    }
]


class BaseChainHandler(ChainHandler):
    """Handler for Base (Ethereum L2) blockchain."""

    CHAIN_ID = 8453  # Base mainnet
    USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Support both new X402_BASE_* and legacy X402_* env via config
        from django.conf import settings
        self.rpc_url = config.get('rpc_url') or getattr(
            settings, 'X402_BASE_RPC_URL', getattr(settings, 'X402_RPC_URL', ''))
        self.signer_private_key = config.get('signer_private_key') or getattr(
            settings, 'X402_BASE_SIGNER_PRIVATE_KEY', getattr(settings, 'X402_SIGNER_PRIVATE_KEY', ''))
        self.signer_address = config.get('signer_address') or getattr(
            settings, 'X402_BASE_SIGNER_ADDRESS', getattr(settings, 'X402_SIGNER_ADDRESS', ''))
        self.gas_limit = config.get('gas_limit', 250000)
        self.tx_timeout_seconds = config.get('tx_timeout_seconds', 120)
        self.max_fee_per_gas_wei = config.get('max_fee_per_gas_wei', 0)
        self.max_priority_fee_per_gas_wei = config.get(
            'max_priority_fee_per_gas_wei', 0)

    @property
    def chain_name(self) -> str:
        return 'base'

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
            raise ValueError('Signature must be 65 bytes')
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
            # Extract authorization data
            authorization = payload.get('payload', {}).get('authorization', {})
            signature = payload.get('signature', '')

            # Build EIP-712 typed data
            extra = requirements.get('extra', {})
            eip712_data = extra.get('eip712', {})

            if not eip712_data:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Missing EIP-712 data in requirements'
                )

            # Encode and recover signer
            signable_message = encode_structured_data(eip712_data)
            recovered_address = Web3().eth.account.recover_message(
                signable_message,
                signature=signature
            )

            payer = self._normalize_address(authorization.get('from', ''))
            recovered = self._normalize_address(recovered_address)

            if payer != recovered:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f'Signature mismatch: expected {payer}, got {recovered}',
                    payer=recovered
                )

            # Validate amounts and addresses match
            pay_to = self._normalize_address(requirements.get('payTo', ''))
            auth_to = self._normalize_address(authorization.get('to', ''))

            if pay_to != auth_to:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f'Recipient mismatch: expected {pay_to}, got {auth_to}'
                )

            max_amount = int(requirements.get('maxAmountRequired', '0'))
            auth_value = int(authorization.get('value', '0'))

            if auth_value > max_amount:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f'Amount exceeds limit: {auth_value} > {max_amount}'
                )

            return VerificationResult(
                is_valid=True,
                payer=payer,
                details={
                    'amount': auth_value,
                    'nonce': authorization.get('nonce'),
                }
            )

        except Exception as e:
            logger.error(f'Base chain verification error: {e}')
            return VerificationResult(
                is_valid=False,
                invalid_reason=f'Verification error: {str(e)}'
            )

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
            rpc_url = self.config.get('rpc_url', '')
            private_key = self.config.get('signer_private_key', '')
            gas_limit = self.config.get('gas_limit', 250000)
            timeout = self.config.get('tx_timeout_seconds', 120)

            if not rpc_url:
                return SettlementResult(
                    success=False,
                    error_reason='RPC URL not configured'
                )

            if not private_key:
                return SettlementResult(
                    success=False,
                    error_reason='Signer private key not configured'
                )

            # Connect to Base chain
            web3 = Web3(HTTPProvider(rpc_url))
            if not web3.is_connected():
                return SettlementResult(
                    success=False,
                    error_reason='Unable to connect to RPC endpoint'
                )

            # Prepare transaction
            account = web3.eth.account.from_key(private_key)
            signer_address = self._normalize_address(account.address)

            authorization = payload.get('payload', {}).get('authorization', {})
            signature = payload.get('signature', '')
            asset_address = self._normalize_address(
                requirements.get('asset', ''))

            # Get USDC contract
            contract = web3.eth.contract(
                address=asset_address,
                abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
            )

            # Prepare parameters
            nonce_bytes = HexBytes(authorization['nonce'])
            v, r, s = self._signature_to_components(signature)

            transfer_fn = contract.functions.transferWithAuthorization(
                self._normalize_address(authorization['from']),
                self._normalize_address(authorization['to']),
                int(authorization['value']),
                int(authorization['validAfter']),
                int(authorization['validBefore']),
                nonce_bytes,
                v,
                r,
                s,
            )

            # Pre-flight simulation
            try:
                transfer_fn.call({'from': signer_address})
            except ContractLogicError as exc:
                error_msg = self._map_contract_error(exc)
                logger.error(f'Settlement simulation failed: {error_msg}')
                return SettlementResult(
                    success=False,
                    error_reason=error_msg
                )
            except BadFunctionCallOutput:
                # Some USDC implementations don't return bool, continue anyway
                logger.warning(
                    'Settlement simulation returned empty data, continuing')

            # Estimate gas
            try:
                estimated_gas = transfer_fn.estimate_gas(
                    {'from': signer_address})
            except Exception:
                estimated_gas = gas_limit

            # Build transaction
            tx_params = {
                'chainId': self.CHAIN_ID,
                'from': signer_address,
                'nonce': web3.eth.get_transaction_count(signer_address),
                'gas': max(estimated_gas, gas_limit),
                'gasPrice': web3.eth.gas_price,
            }

            transaction = transfer_fn.build_transaction(tx_params)
            signed = web3.eth.account.sign_transaction(
                transaction, private_key=private_key)

            # Send transaction
            tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)
            logger.info(f'Settlement transaction submitted: {tx_hash.hex()}')

            # Wait for confirmation
            receipt = web3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=timeout)

            if receipt.status != 1:
                return SettlementResult(
                    success=False,
                    transaction_hash=tx_hash.hex(),
                    error_reason='Transaction reverted on-chain'
                )

            return SettlementResult(
                success=True,
                transaction_hash=tx_hash.hex(),
                payer=self._normalize_address(authorization['from']),
                details={
                    'block': receipt.blockNumber,
                    'gas_used': receipt.gasUsed,
                }
            )

        except Exception as e:
            logger.error(f'Base chain settlement error: {e}')
            return SettlementResult(
                success=False,
                error_reason=f'Settlement error: {str(e)}'
            )

    def _map_contract_error(self, exc: ContractLogicError) -> str:
        """Map contract errors to user-friendly messages."""
        message = str(exc).lower()
        if 'amount exceeds balance' in message or 'insufficient balance' in message:
            return 'Payer has insufficient USDC balance'
        if 'insufficient funds' in message:
            return 'Facilitator has insufficient ETH for gas'
        return 'Settlement transaction reverted on-chain'

    def get_explorer_url(self, tx_hash: str) -> str:
        """Get BaseScan explorer URL."""
        return f"https://basescan.org/tx/{tx_hash}"
