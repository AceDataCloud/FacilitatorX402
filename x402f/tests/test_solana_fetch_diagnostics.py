import unittest
from unittest import mock

from x402f.chain_handlers.solana_exact import SolanaExactHandler


def _handler() -> SolanaExactHandler:
    return SolanaExactHandler(
        config={"rpc_url": "https://rpc.test", "signer_private_key": "", "signer_address": "", "fee_payer": ""}
    )


class SolanaFetchDiagnosticsTests(unittest.TestCase):
    def test_rpc_unavailable_sets_actionable_error(self):
        h = _handler()
        # Simulate every getTransaction call raising (RPC unreachable).
        with mock.patch(
            "x402f.chain_handlers.solana_exact.urllib.request.urlopen", side_effect=OSError("conn refused")
        ):
            with mock.patch("x402f.chain_handlers.solana_exact.time.sleep", return_value=None):
                tx, meta = h._fetch_transaction_b64_by_signature("sig123")
        self.assertIsNone(tx)
        self.assertIsNone(meta)
        self.assertIn("RPC unavailable", h._last_fetch_error)

    def test_clean_null_result_marks_not_found(self):
        h = _handler()

        class _Resp:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            def read(self_inner):
                return b'{"jsonrpc":"2.0","id":1,"result":null}'

        with mock.patch("x402f.chain_handlers.solana_exact.urllib.request.urlopen", return_value=_Resp()):
            with mock.patch("x402f.chain_handlers.solana_exact.time.sleep", return_value=None):
                tx, meta = h._fetch_transaction_b64_by_signature("sigABC")
        self.assertIsNone(tx)
        self.assertIn("not found on-chain", h._last_fetch_error)


if __name__ == "__main__":
    unittest.main()
