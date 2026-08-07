from __future__ import annotations

from loguru import logger
from solders.pubkey import Pubkey
from x402.mechanisms.svm.constants import (
    COMPUTE_BUDGET_PROGRAM_ADDRESS,
    ERR_FEE_PAYER_MISSING,
    ERR_FEE_PAYER_NOT_MANAGED,
    ERR_FEE_PAYER_TRANSFERRING,
    ERR_INVALID_COMPUTE_LIMIT,
    ERR_INVALID_COMPUTE_PRICE,
    ERR_MEMO_COUNT,
    ERR_MEMO_MISMATCH,
    ERR_MINT_MISMATCH,
    ERR_NETWORK_MISMATCH,
    ERR_NO_TRANSFER_INSTRUCTION,
    ERR_RECIPIENT_MISMATCH,
    ERR_SIMULATION_FAILED,
    ERR_TRANSACTION_DECODE_FAILED,
    ERR_UNSUPPORTED_SCHEME,
    LIGHTHOUSE_PROGRAM_ADDRESS,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    MEMO_PROGRAM_ADDRESS,
    SCHEME_EXACT,
    TOKEN_2022_PROGRAM_ADDRESS,
    TOKEN_PROGRAM_ADDRESS,
)
from x402.mechanisms.svm.exact import ExactSvmFacilitatorScheme
from x402.mechanisms.svm.types import ExactSvmPayload
from x402.mechanisms.svm.utils import decode_transaction_from_payload, derive_ata
from x402.schemas import PaymentPayload, PaymentRequirements, VerifyResponse

DEFAULT_COMPUTE_UNIT_LIMIT = 100_000
DEFAULT_COMPUTE_UNIT_PRICE = 5_000
ERR_DUPLICATE_TRANSFER = "invalid_exact_svm_payload_multiple_transfer_instructions"
ERR_COMPUTE_INSTRUCTION_COUNT = "invalid_exact_svm_payload_compute_instruction_count"
ERR_AMOUNT_MISMATCH = "invalid_exact_svm_payload_amount_mismatch"
ERR_FEE_PAYER_ACCOUNT_MISMATCH = "invalid_exact_svm_payload_fee_payer_account_mismatch"
ERR_FEE_PAYER_IN_INSTRUCTION = "invalid_exact_svm_payload_fee_payer_in_instruction"
ERR_SIGNER_SET_MISMATCH = "invalid_exact_svm_payload_signer_set_mismatch"
PHANTOM_FEE_PAYER_ASSERTION = bytes.fromhex("06040203000001000000000000000000")


def _is_safe_lighthouse_fee_payer_assertion(instruction, program: Pubkey, lighthouse_program: Pubkey) -> bool:
    return (
        program == lighthouse_program
        and list(instruction.accounts) == [0]
        and bytes(instruction.data) == PHANTOM_FEE_PAYER_ASSERTION
    )


class OutcomeExactSvmFacilitatorScheme(ExactSvmFacilitatorScheme):
    """Verify payment outcome while bounding the facilitator's fee exposure."""

    def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        context=None,
    ) -> VerifyResponse:
        del context
        svm_payload = ExactSvmPayload.from_dict(payload.payload)
        network = str(requirements.network)

        if payload.accepted.scheme != SCHEME_EXACT or requirements.scheme != SCHEME_EXACT:
            return self._invalid(ERR_UNSUPPORTED_SCHEME)
        if str(payload.accepted.network) != network:
            return self._invalid(ERR_NETWORK_MISMATCH)

        extra = requirements.extra or {}
        fee_payer = extra.get("feePayer")
        if not fee_payer or not isinstance(fee_payer, str):
            return self._invalid(ERR_FEE_PAYER_MISSING)
        signer_addresses = self._signer.get_addresses()
        if fee_payer not in signer_addresses:
            return self._invalid(ERR_FEE_PAYER_NOT_MANAGED)

        try:
            tx = decode_transaction_from_payload(svm_payload)
        except Exception:
            return self._invalid(ERR_TRANSACTION_DECODE_FAILED)

        message = tx.message
        instructions = list(message.instructions)
        accounts = list(message.account_keys)
        programs = [accounts[ix.program_id_index] for ix in instructions]
        if not accounts or str(accounts[0]) != fee_payer:
            return self._invalid_layout(ERR_FEE_PAYER_ACCOUNT_MISMATCH, programs)
        if message.header.num_required_signatures != 2:
            return self._invalid_layout(ERR_SIGNER_SET_MISMATCH, programs)

        compute_program = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM_ADDRESS)
        token_programs = {
            Pubkey.from_string(TOKEN_PROGRAM_ADDRESS),
            Pubkey.from_string(TOKEN_2022_PROGRAM_ADDRESS),
        }
        lighthouse_program = Pubkey.from_string(LIGHTHOUSE_PROGRAM_ADDRESS)
        memo_program = Pubkey.from_string(MEMO_PROGRAM_ADDRESS)
        limit_values: list[int] = []
        price_values: list[int] = []
        transfer_instructions = []
        memo_instructions = []

        for instruction, program in zip(instructions, programs, strict=True):
            if 0 in instruction.accounts and not _is_safe_lighthouse_fee_payer_assertion(
                instruction, program, lighthouse_program
            ):
                return self._invalid_layout(ERR_FEE_PAYER_IN_INSTRUCTION, programs)

            data = bytes(instruction.data)
            if program == compute_program:
                if len(data) == 5 and data[0] == 2:
                    limit_values.append(int.from_bytes(data[1:5], "little"))
                elif len(data) == 9 and data[0] == 3:
                    price_values.append(int.from_bytes(data[1:9], "little"))
                else:
                    return self._invalid_layout(ERR_INVALID_COMPUTE_LIMIT, programs)
            elif program in token_programs and len(data) == 10 and data[0] == 12:
                transfer_instructions.append(instruction)
            elif program == memo_program:
                memo_instructions.append(instruction)

        if len(limit_values) != 1 or len(price_values) != 1:
            return self._invalid_layout(ERR_COMPUTE_INSTRUCTION_COUNT, programs)

        max_units = int(extra.get("computeUnitLimit") or DEFAULT_COMPUTE_UNIT_LIMIT)
        if limit_values[0] > max_units:
            return self._invalid_layout(ERR_INVALID_COMPUTE_LIMIT, programs)
        max_price = min(
            int(extra.get("computeUnitPriceMicroLamports") or DEFAULT_COMPUTE_UNIT_PRICE),
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
        )
        if price_values[0] > max_price:
            return self._invalid_layout(ERR_INVALID_COMPUTE_PRICE, programs)

        if not transfer_instructions:
            return self._invalid_layout(ERR_NO_TRANSFER_INSTRUCTION, programs)
        if len(transfer_instructions) > 1:
            return self._invalid_layout(ERR_DUPLICATE_TRANSFER, programs)

        transfer = transfer_instructions[0]
        transfer_accounts = list(transfer.accounts)
        transfer_data = bytes(transfer.data)
        if len(transfer_accounts) < 4:
            return self._invalid_layout(ERR_NO_TRANSFER_INSTRUCTION, programs)

        payer = str(accounts[transfer_accounts[3]])
        transfer_program = accounts[transfer.program_id_index]
        mint = accounts[transfer_accounts[1]]
        destination = accounts[transfer_accounts[2]]
        authority = accounts[transfer_accounts[3]]
        amount = int.from_bytes(transfer_data[1:9], "little")

        if str(authority) in signer_addresses:
            return self._invalid(ERR_FEE_PAYER_TRANSFERRING, payer)
        if len(accounts) < 2 or authority != accounts[1]:
            return self._invalid(ERR_SIGNER_SET_MISMATCH, payer)
        if str(mint) != requirements.asset:
            return self._invalid(ERR_MINT_MISMATCH, payer)
        expected_destination = derive_ata(
            requirements.pay_to,
            requirements.asset,
            str(transfer_program),
        )
        if str(destination) != expected_destination:
            return self._invalid(ERR_RECIPIENT_MISMATCH, payer)
        if amount != int(requirements.amount):
            return self._invalid(ERR_AMOUNT_MISMATCH, payer)

        expected_memo = extra.get("memo")
        if expected_memo and isinstance(expected_memo, str):
            matching_memos = []
            for instruction in memo_instructions:
                try:
                    value = bytes(instruction.data).decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if value == expected_memo:
                    matching_memos.append(instruction)
            if len(matching_memos) != 1:
                reason = ERR_MEMO_COUNT if not matching_memos else ERR_MEMO_MISMATCH
                return self._invalid(reason, payer)

        try:
            signed = self._signer.sign_transaction(svm_payload.transaction, fee_payer, network)
            self._signer.simulate_transaction(signed, network)
        except Exception as exc:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_SIMULATION_FAILED,
                invalid_message=str(exc),
                payer=payer,
            )
        return VerifyResponse(is_valid=True, payer=payer)

    @staticmethod
    def _invalid(reason: str, payer: str = "") -> VerifyResponse:
        return VerifyResponse(is_valid=False, invalid_reason=reason, payer=payer)

    @classmethod
    def _invalid_layout(cls, reason: str, programs: list[Pubkey]) -> VerifyResponse:
        logger.warning(
            "SVM payment layout rejected: reason={} instruction_count={} programs={}",
            reason,
            len(programs),
            [str(program) for program in programs],
        )
        return cls._invalid(reason)
