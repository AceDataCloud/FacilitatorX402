import unittest


try:
    from solders.pubkey import Pubkey
    from spl.memo.constants import MEMO_PROGRAM_ID
    from spl.token.instructions import get_associated_token_address

    from x402f.chain_handlers.solana_chain import (
        SolanaChainHandler,
        COMPUTE_BUDGET_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
    )

    SOLANA_DEPS_AVAILABLE = True
except Exception:
    SOLANA_DEPS_AVAILABLE = False


@unittest.skipUnless(SOLANA_DEPS_AVAILABLE, "Solana dependencies are not installed")
class SolanaInstructionStructureTests(unittest.TestCase):
    def _make_handler(self) -> "SolanaChainHandler":
        return SolanaChainHandler(
            config={
                "rpc_url": "",
                "signer_private_key": "",
                "signer_address": "",
                "fee_payer": "",
            }
        )

    def _make_tx(self, account_keys, instructions):
        message = type(
            "Msg",
            (),
            {
                "instructions": instructions,
                "account_keys": account_keys,
            },
        )
        return type("Tx", (), {"message": message})

    def test_allows_memo_after_transfer(self):
        handler = self._make_handler()

        pay_to = Pubkey.new_unique()
        mint = Pubkey.from_string(handler.USDC_MINT)
        dest = get_associated_token_address(pay_to, mint)
        source = Pubkey.new_unique()
        authority = Pubkey.new_unique()
        fee_payer = Pubkey.new_unique()

        account_keys = [
            fee_payer,
            COMPUTE_BUDGET_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            MEMO_PROGRAM_ID,
            source,
            mint,
            dest,
            authority,
            pay_to,
        ]

        class Ix:
            def __init__(self, program_id_index, accounts, data):
                self.program_id_index = program_id_index
                self.accounts = accounts
                self.data = data

        cb_limit = Ix(1, [], bytes([2]) + (250000).to_bytes(4, "little"))
        cb_price = Ix(1, [], bytes([3]) + (1_000_000).to_bytes(8, "little"))
        amount = 1000
        transfer_data = bytes([12]) + amount.to_bytes(8, "little") + bytes([6])
        transfer_ix = Ix(2, [5, 6, 7, 8], transfer_data)
        memo_ix = Ix(4, [], b"hello")

        tx = self._make_tx(
            account_keys=account_keys,
            instructions=[cb_limit, cb_price, transfer_ix, memo_ix],
        )

        requirements = {
            "maxAmountRequired": str(amount),
            "asset": handler.USDC_MINT,
            "payTo": str(pay_to),
        }

        valid, error, transfer_details = handler._verify_instruction_structure(
            tx, requirements
        )
        self.assertTrue(valid)
        self.assertIsNone(error)
        self.assertIsNotNone(transfer_details)

    def test_rejects_unexpected_instructions(self):
        handler = self._make_handler()

        pay_to = Pubkey.new_unique()
        mint = Pubkey.from_string(handler.USDC_MINT)
        dest = get_associated_token_address(pay_to, mint)
        source = Pubkey.new_unique()
        authority = Pubkey.new_unique()
        fee_payer = Pubkey.new_unique()
        unknown_program = Pubkey.new_unique()

        account_keys = [
            fee_payer,
            COMPUTE_BUDGET_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            unknown_program,
            source,
            mint,
            dest,
            authority,
            pay_to,
        ]

        class Ix:
            def __init__(self, program_id_index, accounts, data):
                self.program_id_index = program_id_index
                self.accounts = accounts
                self.data = data

        cb_limit = Ix(1, [], bytes([2]) + (250000).to_bytes(4, "little"))
        cb_price = Ix(1, [], bytes([3]) + (1_000_000).to_bytes(8, "little"))
        amount = 1000
        transfer_data = bytes([12]) + amount.to_bytes(8, "little") + bytes([6])
        transfer_ix = Ix(2, [5, 6, 7, 8], transfer_data)
        unknown_ix = Ix(4, [], b"boom")

        tx = self._make_tx(
            account_keys=account_keys,
            instructions=[cb_limit, cb_price, unknown_ix, transfer_ix],
        )

        requirements = {
            "maxAmountRequired": str(amount),
            "asset": handler.USDC_MINT,
            "payTo": str(pay_to),
        }

        valid, error, transfer_details = handler._verify_instruction_structure(
            tx, requirements
        )
        self.assertFalse(valid)
        self.assertIsNotNone(error)
        self.assertIn("Unexpected instruction", error)
        self.assertIsNone(transfer_details)

