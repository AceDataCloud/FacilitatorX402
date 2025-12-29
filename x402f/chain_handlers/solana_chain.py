"""
Solana chain handler for x402 protocol.

Based on x402 specification: specs/schemes/exact/scheme_exact_svm.md
Reference: https://github.com/coinbase/x402

The x402 protocol for Solana (SVM) uses partially-signed transactions:
1. Client creates a transaction with SPL Token transfer
2. Client signs the transaction
3. Facilitator verifies and adds signature as fee payer
4. Facilitator submits to network
"""
from typing import Dict, Any, Optional, Tuple
import base58
import base64
import json
import time
import hashlib
from loguru import logger

try:
    from solders.pubkey import Pubkey
    from solders.keypair import Keypair
    from solders.signature import Signature as SolSignature
    from solders.transaction import VersionedTransaction
    from solders.instruction import Instruction, CompiledInstruction
    from solders.message import MessageV0
    from solders.hash import Hash as Blockhash
    from solana.rpc.api import Client
    from solana.rpc.commitment import Confirmed
    from solana.rpc.types import TxOpts
    from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
    from spl.token.instructions import get_associated_token_address
    SOLANA_AVAILABLE = True
except ImportError:
    SOLANA_AVAILABLE = False
    logger.warning("solana-py not installed. Solana chain handler will not work.")

from .base import ChainHandler, VerificationResult, SettlementResult


# Solana program IDs
COMPUTE_BUDGET_PROGRAM_ID = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
TOKEN_2022_PROGRAM_ID = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
MEMO_PROGRAM_ID_V1 = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
MEMO_PROGRAM_ID_V2 = Pubkey.from_string("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")
MEMO_PROGRAM_IDS = {str(MEMO_PROGRAM_ID_V1), str(MEMO_PROGRAM_ID_V2)}


class SolanaChainHandler(ChainHandler):
    """
    Handler for Solana blockchain using x402 exact_svm scheme.

    Implements verification and settlement according to:
    https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md
    """

    USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
    CLUSTER = 'mainnet-beta'

    # x402 spec: compute unit price must not exceed 5 lamports
    MAX_COMPUTE_UNIT_PRICE = 5

    @property
    def chain_name(self) -> str:
        return 'solana'

    def validate_address(self, address: str) -> bool:
        """Validate Solana address format (base58)."""
        try:
            decoded = base58.b58decode(address)
            return len(decoded) == 32
        except Exception:
            return False

    def _deserialize_transaction(self, transaction_b64: str) -> Optional[VersionedTransaction]:
        """Deserialize base64-encoded transaction."""
        try:
            transaction_bytes = base64.b64decode(transaction_b64)
            return VersionedTransaction.from_bytes(transaction_bytes)
        except Exception as e:
            logger.error(f'Failed to deserialize transaction: {e}')
            return None

    @staticmethod
    def _extract_transaction_b64(payload: Dict[str, Any]) -> Optional[str]:
        """
        Extract base64-encoded transaction from a payment payload.

        Accepts multiple wire formats:
        - payload.payload.serializedTransaction (CDP / Solana docs)
        - payload.payload.transaction (legacy/internal)
        - payload.payload.payload (legacy/internal)
        - payload.payload (string)
        """
        raw_payload = payload.get('payload')
        if isinstance(raw_payload, dict):
            return (
                raw_payload.get('serializedTransaction')
                or raw_payload.get('serialized_transaction')
                or raw_payload.get('transaction')
                or raw_payload.get('payload')
            )
        if isinstance(raw_payload, str):
            return raw_payload
        return None

    @staticmethod
    def _compute_nonce_from_tx_b64(transaction_b64: str) -> Optional[str]:
        try:
            tx_bytes = base64.b64decode(transaction_b64)
            digest = hashlib.sha256(tx_bytes).hexdigest()[:32]
            return f"solana:{digest}"
        except Exception:
            return None

    def _verify_instruction_structure(
        self,
        tx: VersionedTransaction,
        requirements: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Verify transaction has correct instruction structure per x402 spec.

        Required instruction programs (in order):
        1. ComputeBudget (SetComputeUnitLimit)
        2. ComputeBudget (SetComputeUnitPrice)
        Remaining instructions:
        - SPL Token TransferChecked (required, exactly one)
        - AssociatedTokenAccount create (optional)
        - Memo (optional)

        Returns: (is_valid, error_reason, transfer_details)
        """
        message = tx.message
        instructions = message.instructions

        # Minimum 3 instructions required
        if len(instructions) < 3:
            return False, f'Expected at least 3 instructions, got {len(instructions)}', None

        # Allow optional ATA create and/or Memo instructions around the transfer.
        # We keep a small cap to avoid accepting arbitrary large instruction lists.
        if len(instructions) > 6:
            return False, f'Expected at most 6 instructions, got {len(instructions)}', None

        # Instruction 0: ComputeBudget
        if not self._is_compute_budget_instruction(message, instructions[0]):
            return False, 'First instruction must be ComputeBudget SetComputeUnitLimit', None

        # Instruction 1: ComputeBudget
        if not self._is_compute_budget_instruction(message, instructions[1]):
            return False, 'Second instruction must be ComputeBudget SetComputeUnitPrice', None

        # Verify price <= 5 lamports per x402 spec (price instruction can be in either slot).
        for compute_ix in (instructions[0], instructions[1]):
            price = self._extract_compute_unit_price(compute_ix)
            if price and price > self.MAX_COMPUTE_UNIT_PRICE:
                return False, f'Compute unit price {price} exceeds maximum {self.MAX_COMPUTE_UNIT_PRICE}', None

        transfer_details: Optional[Dict[str, Any]] = None
        transfer_index: Optional[int] = None
        ata_indices: list[int] = []

        # Remaining instructions: memo/ata/transferchecked (exactly one transferchecked)
        for idx in range(2, len(instructions)):
            instruction = instructions[idx]
            program_id = message.account_keys[instruction.program_id_index]
            program_id_str = str(program_id)

            if program_id_str in MEMO_PROGRAM_IDS:
                continue

            if self._is_ata_create_instruction(message, instruction):
                ata_indices.append(idx)
                continue

            if program_id == TOKEN_PROGRAM_ID or program_id == TOKEN_2022_PROGRAM_ID:
                if transfer_details is not None:
                    return False, 'Multiple TransferChecked instructions are not allowed', None
                transfer_details = self._verify_transfer_instruction(message, instruction, requirements)
                if not transfer_details:
                    return False, 'Invalid TransferChecked instruction', None
                transfer_index = idx
                continue

            allowed_programs = sorted({
                str(ASSOCIATED_TOKEN_PROGRAM_ID),
                *MEMO_PROGRAM_IDS,
                str(TOKEN_PROGRAM_ID),
                str(TOKEN_2022_PROGRAM_ID),
            })
            return (
                False,
                f'Unexpected instruction at index {idx}: program_id={program_id_str} (allowed={allowed_programs})',
                None,
            )

        if transfer_details is None or transfer_index is None:
            return False, 'Missing TransferChecked instruction', None

        # If present, ATA create must be before the transfer.
        if ata_indices and any(i > transfer_index for i in ata_indices):
            return False, 'ATA Create instruction must appear before TransferChecked', None

        return True, None, transfer_details

    def _is_compute_budget_instruction(self, message, instruction: CompiledInstruction) -> bool:
        """Check if instruction is a ComputeBudget instruction."""
        program_id_idx = instruction.program_id_index
        program_id = message.account_keys[program_id_idx]
        return program_id == COMPUTE_BUDGET_PROGRAM_ID

    def _is_ata_create_instruction(self, message, instruction: CompiledInstruction) -> bool:
        """Check if instruction is an AssociatedTokenAccount create instruction."""
        program_id_idx = instruction.program_id_index
        program_id = message.account_keys[program_id_idx]
        return program_id == ASSOCIATED_TOKEN_PROGRAM_ID

    def _extract_compute_unit_price(self, instruction: CompiledInstruction) -> Optional[int]:
        """Extract compute unit price from ComputeBudget instruction."""
        try:
            # SetComputeUnitPrice instruction data format:
            # [discriminator: u8, micro_lamports: u64]
            data = bytes(instruction.data)
            if len(data) >= 9 and data[0] == 3:  # discriminator 3 = SetComputeUnitPrice
                # Extract u64 micro_lamports (little-endian)
                micro_lamports = int.from_bytes(data[1:9], 'little')
                # Convert micro_lamports to lamports
                return micro_lamports // 1_000_000
            return None
        except Exception:
            return None

    def _verify_transfer_instruction(
        self,
        message,
        instruction: CompiledInstruction,
        requirements: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Verify SPL Token TransferChecked instruction.

        Returns transfer details if valid, None otherwise.
        """
        try:
            # Check program is Token or Token-2022
            program_id_idx = instruction.program_id_index
            program_id = message.account_keys[program_id_idx]

            if program_id != TOKEN_PROGRAM_ID and program_id != TOKEN_2022_PROGRAM_ID:
                logger.error(f'Invalid program ID for transfer: {program_id}')
                return None

            # TransferChecked instruction data format:
            # [discriminator: u8, amount: u64, decimals: u8]
            data = bytes(instruction.data)
            if len(data) < 10 or data[0] != 12:  # discriminator 12 = TransferChecked
                logger.error('Invalid TransferChecked instruction discriminator')
                return None

            # Extract amount (u64 little-endian)
            amount = int.from_bytes(data[1:9], 'little')
            decimals = data[9]

            # Verify amount matches requirements exactly (per x402 spec)
            max_amount = int(requirements.get('maxAmountRequired', '0'))
            if amount != max_amount:
                logger.error(f'Amount mismatch: {amount} != {max_amount}')
                return None

            # Extract account indices from instruction
            # TransferChecked accounts: [source, mint, destination, authority]
            account_indices = instruction.accounts
            if len(account_indices) < 4:
                logger.error('TransferChecked requires at least 4 accounts')
                return None

            source_idx = account_indices[0]
            mint_idx = account_indices[1]
            dest_idx = account_indices[2]
            authority_idx = account_indices[3]

            source = message.account_keys[source_idx]
            mint = message.account_keys[mint_idx]
            dest = message.account_keys[dest_idx]
            authority = message.account_keys[authority_idx]

            # Verify mint matches requirements
            required_asset = requirements.get('asset', self.USDC_MINT)
            if str(mint) != required_asset:
                logger.error(f'Mint mismatch: {mint} != {required_asset}')
                return None

            # Verify destination is ATA for (payTo, mint)
            pay_to_str = requirements.get('payTo', '') or requirements.get('pay_to', '')
            if not pay_to_str:
                logger.error('payTo missing in requirements')
                return None
            pay_to = Pubkey.from_string(pay_to_str)
            expected_dest = get_associated_token_address(pay_to, mint)

            if dest != expected_dest:
                logger.error(f'Destination mismatch: {dest} != {expected_dest}')
                return None

            return {
                'amount': amount,
                'mint': str(mint),
                'source': str(source),
                'destination': str(dest),
                'authority': str(authority),
                'decimals': decimals,
            }

        except Exception as e:
            logger.error(f'Transfer instruction verification error: {e}')
            return None

    def _verify_fee_payer_not_in_instructions(
        self,
        tx: VersionedTransaction,
        facilitator_pubkey: Pubkey
    ) -> bool:
        """
        Verify facilitator fee payer does NOT appear in any instruction accounts.

        This is a critical security check per x402 spec.
        """
        message = tx.message

        # Check each instruction's accounts
        for instruction in message.instructions:
            for account_idx in instruction.accounts:
                account = message.account_keys[account_idx]
                if account == facilitator_pubkey:
                    logger.error(f'Fee payer appears in instruction accounts: security violation')
                    return False

        return True

    def verify_signature(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> VerificationResult:
        """
        Verify Solana transaction according to x402 exact_svm scheme.

        Payload structure:
        {
            "x402Version": 1,
            "scheme": "exact",
            "network": "solana",
            "payload": "<base64-encoded serialized partially-signed transaction>"
        }
        """
        if not SOLANA_AVAILABLE:
            return VerificationResult(
                is_valid=False,
                invalid_reason='Solana library not installed'
            )

        try:
            if not isinstance(requirements, dict):
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Invalid payment requirements'
                )

            facilitator_address = self.config.get('signer_address', '')
            if not facilitator_address:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Facilitator address not configured'
                )

            required_fields = ['payTo', 'asset', 'maxAmountRequired']
            missing = [f for f in required_fields if not requirements.get(f)]
            if missing:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f"Missing payment requirements: {', '.join(missing)}"
                )

            pay_to = requirements.get('payTo') or requirements.get('pay_to')
            if not self.validate_address(pay_to or ''):
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Invalid payTo address'
                )

            try:
                max_amount_required = int(requirements.get('maxAmountRequired'))
            except Exception:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Invalid maxAmountRequired'
                )
            if max_amount_required <= 0:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='maxAmountRequired must be positive'
                )

            asset = requirements.get('asset')
            if not asset:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Missing asset in requirements'
                )

            fee_payer_hint = (requirements.get('extra') or {}).get('feePayer')
            if fee_payer_hint and fee_payer_hint != facilitator_address:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Fee payer in requirements does not match facilitator configuration'
                )

            # Extract base64-encoded transaction
            transaction_b64 = self._extract_transaction_b64(payload)
            if not transaction_b64:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Missing transaction payload'
                )

            # Deserialize transaction
            tx = self._deserialize_transaction(transaction_b64)
            if not tx:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Failed to deserialize transaction'
                )

            # Get facilitator pubkey
            facilitator_pubkey = Pubkey.from_string(facilitator_address)

            # Verify facilitator is the fee payer
            message = tx.message
            fee_payer = message.account_keys[0]  # First account is always fee payer
            if fee_payer != facilitator_pubkey:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=f'Fee payer mismatch: expected {facilitator_pubkey}, got {fee_payer}'
                )

            # Verify facilitator does NOT appear in instruction accounts
            if not self._verify_fee_payer_not_in_instructions(tx, facilitator_pubkey):
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Fee payer must not appear in instruction accounts'
                )

            # Verify instruction structure
            valid, error, transfer_details = self._verify_instruction_structure(tx, requirements)
            if not valid:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=error or 'Invalid instruction structure'
                )

            # Extract payer (authority) from transfer details
            payer = transfer_details.get('authority', '')

            # Derive a stable nonce from the submitted transaction bytes.
            # This avoids relying on signature ordering (fee payer is signer #0).
            nonce = self._compute_nonce_from_tx_b64(transaction_b64)
            if not nonce:
                return VerificationResult(
                    is_valid=False,
                    invalid_reason='Unable to derive transaction nonce'
                )

            logger.info(f'Solana transaction verified: payer={payer}, amount={transfer_details["amount"]}')

            return VerificationResult(
                is_valid=True,
                payer=payer,
                details={
                    'amount': transfer_details['amount'],
                    'mint': transfer_details['mint'],
                    'nonce': nonce,
                    'transaction': transaction_b64,
                }
            )

        except Exception as e:
            logger.error(f'Solana chain verification error: {e}')
            import traceback
            logger.error(traceback.format_exc())
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
        Settle payment on Solana by adding facilitator signature and submitting.

        Per x402 spec:
        1. Take user's partially-signed transaction
        2. Add facilitator's signature as fee payer
        3. Submit to Solana network
        4. Wait for confirmation
        """
        if not SOLANA_AVAILABLE:
            return SettlementResult(
                success=False,
                error_reason='Solana library not installed'
            )

        try:
            # Get configuration
            rpc_url = self.config.get('rpc_url', 'https://api.mainnet-beta.solana.com')
            signer_private_key = self.config.get('signer_private_key', '')

            if not signer_private_key:
                return SettlementResult(
                    success=False,
                    error_reason='Solana signer private key not configured'
                )

            # Connect to Solana
            client = Client(rpc_url)

            # Load facilitator keypair
            try:
                private_key_bytes = base58.b58decode(signer_private_key)
                facilitator_keypair = Keypair.from_bytes(private_key_bytes)
            except Exception as e:
                return SettlementResult(
                    success=False,
                    error_reason=f'Invalid signer private key: {e}'
                )

            # Extract partially-signed transaction from payload
            transaction_b64 = self._extract_transaction_b64(payload)
            if not transaction_b64:
                return SettlementResult(
                    success=False,
                    error_reason='Missing transaction payload'
                )

            # Deserialize transaction
            tx = self._deserialize_transaction(transaction_b64)
            if not tx:
                return SettlementResult(
                    success=False,
                    error_reason='Failed to deserialize transaction'
                )

            # Sign as fee payer (signature index 0) for VersionedTransaction.
            try:
                message_bytes = bytes(tx.message)
                fee_payer_sig = facilitator_keypair.sign_message(message_bytes)
                required = int(tx.message.header.num_required_signatures)
                signatures = list(tx.signatures)
                if len(signatures) < required:
                    signatures.extend([SolSignature.default()] * (required - len(signatures)))
                if len(signatures) != required:
                    signatures = signatures[:required]
                if required <= 0:
                    return SettlementResult(success=False, error_reason='Invalid signature header')
                signatures[0] = fee_payer_sig
                tx = VersionedTransaction.populate(tx.message, signatures)
            except Exception as exc:
                logger.error(f'Failed to sign solana transaction: {exc}')
                return SettlementResult(
                    success=False,
                    error_reason=f'Failed to sign transaction: {exc}'
                )

            # Submit transaction
            try:
                try:
                    tx_response = client.send_raw_transaction(
                        bytes(tx),
                        opts=TxOpts(
                            skip_preflight=False,
                            skip_confirmation=False,
                            max_retries=3,
                            preflight_commitment=Confirmed,
                        ),
                    )
                except Exception as exc:
                    # Public Solana RPC endpoints can be slightly out-of-sync; if preflight
                    # rejects a brand-new blockhash, retry without preflight.
                    msg = str(exc)
                    if 'Blockhash not found' not in msg and 'BlockhashNotFound' not in msg:
                        raise
                    tx_response = client.send_raw_transaction(
                        bytes(tx),
                        opts=TxOpts(
                            skip_preflight=True,
                            skip_confirmation=False,
                            max_retries=3,
                        ),
                    )
            except Exception as exc:
                return SettlementResult(
                    success=False,
                    error_reason=f'Send transaction failed: {exc}'
                )

            tx_hash = str(getattr(tx_response, 'value', tx_response))
            logger.info(f'Solana settlement transaction submitted: {tx_hash}')

            # Wait for confirmation (best effort)
            try:
                client.confirm_transaction(
                    SolSignature.from_string(tx_hash),
                    commitment=Confirmed,
                )
            except Exception as e:
                logger.warning(f'Confirmation timeout: {e}')

            payer = None
            try:
                # authority/payer was validated during verify; here we return fee payer address
                payer = str(facilitator_keypair.pubkey())
            except Exception:
                payer = None

            return SettlementResult(
                success=True,
                transaction_hash=tx_hash,
                payer=payer,
                details={
                    'mint': requirements.get('asset', self.USDC_MINT),
                }
            )

        except Exception as e:
            logger.error(f'Solana chain settlement error: {e}')
            import traceback
            logger.error(traceback.format_exc())
            return SettlementResult(
                success=False,
                error_reason=f'Settlement error: {str(e)}'
            )

    def get_explorer_url(self, tx_hash: str) -> str:
        """Get Solscan explorer URL."""
        return f"https://solscan.io/tx/{tx_hash}"
