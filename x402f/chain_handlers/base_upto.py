"""Handler for the x402 `upto` scheme on Base (Ethereum L2).

Implements the x402 `upto` scheme using Uniswap Permit2 + the foundation's
`x402UptoPermit2Proxy` contract. The client signs a *maximum* amount, the
server settles the *actual* amount at request completion (used for chat / LLM
metered billing).

This class is also the base for other EVM-chain upto handlers (e.g.
`SkaleUptoHandler`) — the Permit2 contract is deployed at the same CREATE2
address on every EVM chain, so the only difference between chains is the
rpc_url / chain_id / signer config passed in.

Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/upto/scheme_upto_evm.md
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from loguru import logger
from web3 import HTTPProvider, Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from .base import ChainHandler, SettlementResult, TransactionStatus, VerificationResult
from .upto_constants import (
    ERC20_READ_ABI,
    PERMIT2_ADDRESS,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
    X402_UPTO_PERMIT2_PROXY_SETTLE_ABI,
    build_upto_permit2_typed_data,
)

# Per scheme spec §4 — scheme-specific error codes plus reused base codes.
ERR_INVALID_SCHEME = "invalid_upto_evm_payload_invalid_scheme"
ERR_NETWORK_MISMATCH = "invalid_upto_evm_payload_network_mismatch"
ERR_INVALID_PAYLOAD = "invalid_upto_evm_payload"
ERR_INVALID_AMOUNT = "invalid_upto_evm_payload_invalid_amount"
ERR_AMOUNT_MISMATCH = "invalid_upto_evm_payload_amount_mismatch"
ERR_TOKEN_MISMATCH = "invalid_upto_evm_payload_token_mismatch"
ERR_INVALID_SPENDER = "invalid_upto_evm_payload_invalid_spender"
ERR_RECIPIENT_MISMATCH = "invalid_upto_evm_payload_recipient_mismatch"
ERR_FACILITATOR_MISMATCH = "invalid_upto_evm_payload_facilitator_mismatch"
ERR_DEADLINE_EXPIRED = "invalid_upto_evm_payload_deadline_expired"
ERR_NOT_YET_VALID = "invalid_upto_evm_payload_not_yet_valid"
ERR_INVALID_SIGNATURE = "invalid_upto_evm_payload_invalid_signature"
ERR_INVALID_SIGNATURE_FORMAT = "invalid_upto_evm_payload_invalid_signature_format"
ERR_INSUFFICIENT_BALANCE = "invalid_upto_evm_payload_insufficient_balance"
ERR_ALLOWANCE_REQUIRED = "PERMIT2_ALLOWANCE_REQUIRED"
ERR_PROXY_NOT_DEPLOYED = "invalid_upto_evm_payload_proxy_not_deployed"
ERR_SIMULATION_FAILED = "invalid_upto_evm_payload_simulation_failed"
ERR_SETTLEMENT_EXCEEDS_AMOUNT = "invalid_upto_evm_payload_settlement_exceeds_amount"

# Tolerate a small clock skew on deadline / validAfter checks (seconds).
_TIME_SKEW_BUFFER = 30

_CUSTOM_ERROR_SELECTORS = {
    "0xfe64b4c7": ERR_SETTLEMENT_EXCEEDS_AMOUNT,
    "0x0f6fae87": ERR_FACILITATOR_MISMATCH,
    "0x756688fe": ERR_INVALID_SIGNATURE,
    "0xa65539fa": ERR_NOT_YET_VALID,
    "0x49e27cff": ERR_INVALID_PAYLOAD,
    "0xac6b05f5": ERR_INVALID_PAYLOAD,
    "0x2c5211c6": ERR_INVALID_PAYLOAD,
}


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _checksum(address: str) -> str:
    return Web3.to_checksum_address(address)


def _split_settle_revert(exc: Exception) -> str:
    """Map proxy revert strings to spec-defined error codes."""
    msg = str(exc) or ""
    lower = msg.lower()
    for selector, error_code in _CUSTOM_ERROR_SELECTORS.items():
        if selector in lower:
            return error_code
    if "amountexceedspermitted" in lower:
        return ERR_SETTLEMENT_EXCEEDS_AMOUNT
    if "unauthorizedfacilitator" in lower:
        return ERR_FACILITATOR_MISMATCH
    if "invalidnonce" in lower:
        return ERR_INVALID_SIGNATURE  # Permit2 nonce already used
    if "invalidsignature" in lower or "signatureexpired" in lower:
        return ERR_INVALID_SIGNATURE
    if "paymenttooearly" in lower:
        return ERR_NOT_YET_VALID
    if "invalidowner" in lower or "invaliddestination" in lower or "invalidamount" in lower:
        return ERR_INVALID_PAYLOAD
    if "amount exceeds balance" in lower or "insufficient balance" in lower:
        return ERR_INSUFFICIENT_BALANCE
    return ERR_SIMULATION_FAILED


class BaseUptoHandler(ChainHandler):
    """Handler for the x402 `upto` scheme on Base.

    Also used as the parent of `SkaleUptoHandler` — the Permit2 + x402 proxy
    contracts are deployed at the same CREATE2 address on every EVM chain, so
    chain-specific behaviour is config-driven (chain_id, rpc_url, signer).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._chain_name = config.get("chain_name", "base")
        self._chain_id = int(config.get("chain_id") or 8453)
        self._rpc_url = config.get("rpc_url", "")
        self._signer_private_key = config.get("signer_private_key", "")
        self._signer_address = config.get("signer_address", "")
        self._gas_limit = int(config.get("gas_limit") or 400000)
        self._tx_timeout_seconds = int(config.get("tx_timeout_seconds") or 120)
        self._max_fee_per_gas_wei = int(config.get("max_fee_per_gas_wei") or 0)
        self._max_priority_fee_per_gas_wei = int(config.get("max_priority_fee_per_gas_wei") or 0)

    @property
    def chain_name(self) -> str:
        return self._chain_name

    def _transaction_gas_limit(self, estimated_gas: int) -> int:
        return max(int(estimated_gas), self._gas_limit)

    def validate_address(self, address: str) -> bool:
        try:
            Web3.to_checksum_address(address)
            return True
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------ verify
    def verify_signature(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
    ) -> VerificationResult:
        """Run spec Phase 3 verification (7 steps).

        Returns VerificationResult with `payer` and `details = {amount, nonce,
        permitted_amount, deadline, valid_after}`.
        """
        try:
            parsed, parse_err = _parse_upto_payload(payload)
            if parse_err:
                return VerificationResult(is_valid=False, invalid_reason=parse_err)

            req_amount = _to_int(requirements.get("amount") or requirements.get("maxAmountRequired"))
            if req_amount is None or req_amount < 0:
                return VerificationResult(is_valid=False, invalid_reason=ERR_INVALID_AMOUNT)

            req_pay_to = requirements.get("payTo") or ""
            req_asset = requirements.get("asset") or ""
            if not req_pay_to or not req_asset:
                return VerificationResult(is_valid=False, invalid_reason=ERR_INVALID_PAYLOAD)

            # 6. Token + recipient + spender + facilitator binding
            if parsed["spender"].lower() != X402_UPTO_PERMIT2_PROXY_ADDRESS.lower():
                return VerificationResult(is_valid=False, invalid_reason=ERR_INVALID_SPENDER)
            if parsed["witness_to"].lower() != req_pay_to.lower():
                return VerificationResult(is_valid=False, invalid_reason=ERR_RECIPIENT_MISMATCH)
            if parsed["permitted_token"].lower() != req_asset.lower():
                return VerificationResult(is_valid=False, invalid_reason=ERR_TOKEN_MISMATCH)

            facilitator_address = (requirements.get("extra") or {}).get("facilitatorAddress") or self._signer_address
            if not facilitator_address:
                return VerificationResult(is_valid=False, invalid_reason=ERR_FACILITATOR_MISMATCH)
            if parsed["witness_facilitator"].lower() != facilitator_address.lower():
                return VerificationResult(is_valid=False, invalid_reason=ERR_FACILITATOR_MISMATCH)

            # 4. permit.permitted.amount == requirements.amount
            # (note: at /settle time the caller swaps requirements.amount to permitted
            #  before re-invoking verify, so this comparison stays correct)
            if parsed["permitted_amount"] != req_amount:
                return VerificationResult(is_valid=False, invalid_reason=ERR_AMOUNT_MISMATCH)

            # 5. deadline + validAfter
            import time

            now = int(time.time())
            if parsed["deadline"] + _TIME_SKEW_BUFFER < now:
                return VerificationResult(is_valid=False, invalid_reason=ERR_DEADLINE_EXPIRED)
            if parsed["valid_after"] > now + _TIME_SKEW_BUFFER:
                return VerificationResult(is_valid=False, invalid_reason=ERR_NOT_YET_VALID)

            # 1. Signature recovery via EIP-712
            typed_data = build_upto_permit2_typed_data(
                chain_id=self._chain_id,
                permitted_token=_checksum(parsed["permitted_token"]),
                permitted_amount=parsed["permitted_amount"],
                nonce=parsed["nonce"],
                deadline=parsed["deadline"],
                witness_to=_checksum(parsed["witness_to"]),
                witness_facilitator=_checksum(parsed["witness_facilitator"]),
                witness_valid_after=parsed["valid_after"],
            )
            try:
                signable = encode_typed_data(full_message=typed_data)
                recovered = Account.recover_message(signable, signature=parsed["signature"])
            except Exception as exc:
                return VerificationResult(
                    is_valid=False, invalid_reason=ERR_INVALID_SIGNATURE_FORMAT, details={"error": str(exc)}
                )
            if recovered.lower() != parsed["from_address"].lower():
                return VerificationResult(
                    is_valid=False,
                    invalid_reason=ERR_INVALID_SIGNATURE,
                    payer=recovered,
                )

            payer = _checksum(parsed["from_address"])

            # 2 + 3. on-chain preflight: allowance + balance
            preflight_err = self._preflight_check(payer, req_asset, req_amount)
            if preflight_err is not None:
                return VerificationResult(is_valid=False, invalid_reason=preflight_err, payer=payer)

            # 7. simulate settle() with the worst-case (max) amount
            sim_err = self._simulate_settle(
                parsed=parsed,
                settlement_amount=req_amount,
            )
            if sim_err is not None:
                return VerificationResult(is_valid=False, invalid_reason=sim_err, payer=payer)

            return VerificationResult(
                is_valid=True,
                payer=payer,
                details={
                    "amount": req_amount,
                    "permitted_amount": parsed["permitted_amount"],
                    "nonce": str(parsed["nonce"]),
                    "deadline": parsed["deadline"],
                    "valid_after": parsed["valid_after"],
                },
            )
        except Exception as exc:
            logger.error("upto verification unexpected error: {}", exc)
            return VerificationResult(is_valid=False, invalid_reason=f"{ERR_SIMULATION_FAILED}: {exc}")

    # ------------------------------------------------------------------ settle
    def settle_payment(
        self,
        payload: Dict[str, Any],
        requirements: Dict[str, Any],
        on_transaction_prepared=None,
    ) -> SettlementResult:
        """Execute `x402UptoPermit2Proxy.settle(...)` with the metered actual amount.

        Caller (PlatformGateway /record) provides `requirements.amount` set to
        the *actual* amount to settle, which must be ≤ permit.permitted.amount.
        Zero settlement skips the on-chain transaction.
        """
        parsed, parse_err = _parse_upto_payload(payload)
        if parse_err:
            return SettlementResult(success=False, error_reason=parse_err)

        settlement_amount = _to_int(requirements.get("amount") or requirements.get("maxAmountRequired"))
        if settlement_amount is None or settlement_amount < 0:
            return SettlementResult(success=False, error_reason=ERR_INVALID_AMOUNT)

        if settlement_amount > parsed["permitted_amount"]:
            return SettlementResult(success=False, error_reason=ERR_SETTLEMENT_EXCEEDS_AMOUNT)

        payer = _checksum(parsed["from_address"])

        # Zero settlement: spec §Phase4 — no on-chain tx, authorization expires unused.
        if settlement_amount == 0:
            logger.info("upto: zero-amount settle, skipping on-chain tx for payer={}", payer)
            return SettlementResult(
                success=True,
                payer=payer,
                transaction_hash="",
                details={"amount": 0, "skipped": True},
            )

        if not self._rpc_url:
            return SettlementResult(success=False, error_reason="RPC URL not configured")
        if not self._signer_private_key:
            return SettlementResult(success=False, error_reason="Signer private key not configured")

        prepared_hash = None
        try:
            web3 = self._web3()
            account = web3.eth.account.from_key(self._signer_private_key)
            signer_address = _checksum(self._signer_address or account.address)

            proxy = web3.eth.contract(
                address=_checksum(X402_UPTO_PERMIT2_PROXY_ADDRESS),
                abi=X402_UPTO_PERMIT2_PROXY_SETTLE_ABI,
            )

            permit_tuple = (
                (_checksum(parsed["permitted_token"]), parsed["permitted_amount"]),
                parsed["nonce"],
                parsed["deadline"],
            )
            witness_tuple = (
                _checksum(parsed["witness_to"]),
                _checksum(parsed["witness_facilitator"]),
                parsed["valid_after"],
            )
            settle_fn = proxy.functions.settle(
                permit_tuple,
                settlement_amount,
                payer,
                witness_tuple,
                HexBytes(parsed["signature"]),
            )

            try:
                settle_fn.call({"from": signer_address})
            except ContractLogicError as exc:
                reason = _split_settle_revert(exc)
                logger.error("upto settle simulation failed: payer={} reason={} raw={}", payer, reason, exc)
                return SettlementResult(success=False, error_reason=reason, payer=payer)
            except BadFunctionCallOutput:
                logger.warning("upto settle simulation returned empty data, continuing to submit")

            try:
                estimated_gas = settle_fn.estimate_gas({"from": signer_address})
            except Exception:
                estimated_gas = self._gas_limit

            tx_params: Dict[str, Any] = {
                "chainId": self._chain_id,
                "from": signer_address,
                "nonce": web3.eth.get_transaction_count(signer_address, "pending"),
                "gas": self._transaction_gas_limit(estimated_gas),
            }
            if self._max_fee_per_gas_wei and self._max_priority_fee_per_gas_wei:
                tx_params["maxFeePerGas"] = self._max_fee_per_gas_wei
                tx_params["maxPriorityFeePerGas"] = self._max_priority_fee_per_gas_wei
            else:
                tx_params["gasPrice"] = web3.eth.gas_price

            tx = settle_fn.build_transaction(tx_params)
            signed = web3.eth.account.sign_transaction(tx, private_key=self._signer_private_key)
            raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
            if raw_tx is None:
                return SettlementResult(success=False, error_reason="Signer returned unexpected encoding")

            prepared_hash = web3.keccak(raw_tx).hex()
            if not prepared_hash.startswith("0x"):
                prepared_hash = "0x" + prepared_hash
            if on_transaction_prepared:
                on_transaction_prepared(prepared_hash)

            tx_hash = web3.eth.send_raw_transaction(raw_tx)
            tx_hash_hex = tx_hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex
            logger.info("upto settle submitted: tx={} payer={} amount={}", tx_hash_hex, payer, settlement_amount)

            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=self._tx_timeout_seconds)
            if receipt.status != 1:
                return SettlementResult(
                    success=False,
                    transaction_hash=tx_hash_hex,
                    payer=payer,
                    error_reason="Settlement transaction reverted on-chain",
                )

            return SettlementResult(
                success=True,
                transaction_hash=tx_hash_hex,
                payer=payer,
                details={
                    "amount": settlement_amount,
                    "block": receipt.blockNumber,
                    "gas_used": receipt.gasUsed,
                },
            )

        except ContractLogicError as exc:
            reason = _split_settle_revert(exc)
            logger.error("upto settle contract error: {} reason={}", exc, reason)
            return SettlementResult(success=False, error_reason=reason, payer=payer)
        except Exception as exc:
            logger.exception("upto settle unexpected error")
            return SettlementResult(
                success=False,
                transaction_hash=prepared_hash,
                error_reason=f"Settlement error: {exc}",
                payer=payer,
            )

    def get_transaction_status(self, tx_hash: str) -> TransactionStatus:
        if not tx_hash:
            return TransactionStatus.UNKNOWN
        try:
            web3 = self._web3()
            receipt = web3.eth.get_transaction_receipt(tx_hash)
            if receipt is None:
                return TransactionStatus.PENDING
            return TransactionStatus.CONFIRMED if receipt.status == 1 else TransactionStatus.FAILED
        except Exception:
            return TransactionStatus.UNKNOWN

    # ------------------------------------------------------------------ helpers
    def _web3(self) -> Web3:
        return Web3(HTTPProvider(self._rpc_url))

    def _preflight_check(self, payer: str, asset: str, amount: int) -> Optional[str]:
        """Pre-flight on-chain: Permit2 allowance + token balance.

        Fails open (returns None) if RPC is unreachable so that signature-only
        verification can still succeed — the simulate step right after will
        catch any actual on-chain problem.
        """
        if not self._rpc_url:
            return None
        try:
            web3 = self._web3()
            token = web3.eth.contract(address=_checksum(asset), abi=ERC20_READ_ABI)
            try:
                allowance = token.functions.allowance(_checksum(payer), _checksum(PERMIT2_ADDRESS)).call()
            except Exception as exc:
                logger.warning("upto preflight allowance read failed (fail-open): {}", exc)
                return None
            if int(allowance) < amount:
                return ERR_ALLOWANCE_REQUIRED
            try:
                balance = token.functions.balanceOf(_checksum(payer)).call()
            except Exception as exc:
                logger.warning("upto preflight balance read failed (fail-open): {}", exc)
                return None
            if int(balance) < amount:
                return ERR_INSUFFICIENT_BALANCE
            return None
        except Exception as exc:
            logger.warning("upto preflight RPC error (fail-open): {}", exc)
            return None

    def _simulate_settle(self, *, parsed: Dict[str, Any], settlement_amount: int) -> Optional[str]:
        """Simulate `x402UptoPermit2Proxy.settle` via eth_call.

        Fails open if RPC is unreachable (same rationale as preflight).
        """
        if not self._rpc_url or not self._signer_private_key:
            return None
        try:
            web3 = self._web3()
            account = web3.eth.account.from_key(self._signer_private_key)
            signer_address = _checksum(self._signer_address or account.address)
            proxy = web3.eth.contract(
                address=_checksum(X402_UPTO_PERMIT2_PROXY_ADDRESS),
                abi=X402_UPTO_PERMIT2_PROXY_SETTLE_ABI,
            )
            permit_tuple = (
                (_checksum(parsed["permitted_token"]), parsed["permitted_amount"]),
                parsed["nonce"],
                parsed["deadline"],
            )
            witness_tuple = (
                _checksum(parsed["witness_to"]),
                _checksum(parsed["witness_facilitator"]),
                parsed["valid_after"],
            )
            try:
                proxy.functions.settle(
                    permit_tuple,
                    settlement_amount,
                    _checksum(parsed["from_address"]),
                    witness_tuple,
                    HexBytes(parsed["signature"]),
                ).call({"from": signer_address})
                return None
            except ContractLogicError as exc:
                return _split_settle_revert(exc)
            except BadFunctionCallOutput:
                # Proxy may not return a bool on this chain; treat as success.
                return None
        except Exception as exc:
            logger.warning("upto simulate RPC error (fail-open): {}", exc)
            return None


def _parse_upto_payload(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    """Extract the permit2Authorization fields from a PaymentPayload envelope."""
    raw = payload.get("payload")
    if not isinstance(raw, dict):
        return {}, ERR_INVALID_PAYLOAD
    signature = raw.get("signature") or payload.get("signature")
    permit2 = raw.get("permit2Authorization") or raw.get("permit2_authorization")
    if not isinstance(permit2, dict) or not signature:
        return {}, ERR_INVALID_PAYLOAD

    permitted = permit2.get("permitted") or {}
    witness = permit2.get("witness") or {}
    permitted_token = permitted.get("token") or ""
    permitted_amount = _to_int(permitted.get("amount"))
    from_addr = permit2.get("from") or ""
    spender = permit2.get("spender") or ""
    nonce_raw = permit2.get("nonce")
    deadline = _to_int(permit2.get("deadline"))
    witness_to = witness.get("to") or ""
    witness_facilitator = witness.get("facilitator") or ""
    valid_after = _to_int(witness.get("validAfter") or witness.get("valid_after"))

    # nonce may be hex (legacy) or decimal string; normalize to int.
    nonce: Optional[int]
    if isinstance(nonce_raw, int):
        nonce = nonce_raw
    elif isinstance(nonce_raw, str) and nonce_raw.startswith(("0x", "0X")):
        try:
            nonce = int(nonce_raw, 16)
        except ValueError:
            nonce = None
    else:
        nonce = _to_int(nonce_raw)

    if (
        permitted_amount is None
        or nonce is None
        or deadline is None
        or valid_after is None
        or not permitted_token
        or not from_addr
        or not spender
        or not witness_to
        or not witness_facilitator
    ):
        return {}, ERR_INVALID_PAYLOAD

    return (
        {
            "signature": signature,
            "from_address": from_addr,
            "spender": spender,
            "nonce": nonce,
            "deadline": deadline,
            "permitted_token": permitted_token,
            "permitted_amount": permitted_amount,
            "witness_to": witness_to,
            "witness_facilitator": witness_facilitator,
            "valid_after": valid_after,
        },
        None,
    )
