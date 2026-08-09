import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db.models import DecimalField, Sum
from django.db.models.functions import Cast
from django.utils import timezone
from solana.rpc.api import Client
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from x402f.models import X402Authorization

PROFILE = "solana-recurring-delegation-v1"
PERIOD_SECONDS = 86_400
ACCOUNT_LEN = 211


class RecurringAuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class RecurringDelegation:
    address: str
    wallet: str
    delegatee: str
    payer: str
    authority_init_id: int
    subscription_authority: str
    mint: str
    current_period_start_ts: int
    period_seconds: int
    expiry_ts: int
    amount_per_period: int
    amount_pulled_in_period: int


def is_recurring_payload(payload: dict[str, Any]) -> bool:
    raw = payload.get("payload") or {}
    return isinstance(raw, dict) and raw.get("authorizationProfile") == PROFILE


def recurring_payload_fields(payload: dict[str, Any]) -> tuple[str, str]:
    raw = payload.get("payload") or {}
    delegation = str(raw.get("delegation") or "")
    request_nonce = str(raw.get("requestNonce") or "")
    if not delegation or not request_nonce or len(request_nonce) > 128:
        raise RecurringAuthorizationError("Recurring authorization payload is incomplete.")
    return delegation, request_nonce


def recurring_nonce(network: str, delegation: str, request_nonce: str) -> str:
    return hashlib.sha256(f"{PROFILE}:{network}:{delegation}:{request_nonce}".encode()).hexdigest()


def _pubkey(data: bytes) -> str:
    return str(Pubkey.from_bytes(data))


def parse_recurring_delegation(address: str, data: bytes) -> RecurringDelegation:
    if len(data) != ACCOUNT_LEN or data[0:2] != b"\x03\x01":
        raise RecurringAuthorizationError("Invalid recurring delegation account.")
    return RecurringDelegation(
        address=address,
        wallet=_pubkey(data[3:35]),
        delegatee=_pubkey(data[35:67]),
        payer=_pubkey(data[67:99]),
        authority_init_id=struct.unpack_from("<q", data, 99)[0],
        subscription_authority=_pubkey(data[107:139]),
        mint=_pubkey(data[139:171]),
        current_period_start_ts=struct.unpack_from("<q", data, 171)[0],
        period_seconds=struct.unpack_from("<Q", data, 179)[0],
        expiry_ts=struct.unpack_from("<q", data, 187)[0],
        amount_per_period=struct.unpack_from("<Q", data, 195)[0],
        amount_pulled_in_period=struct.unpack_from("<Q", data, 203)[0],
    )


def _rpc() -> Client:
    if not settings.X402_SOLANA_RPC_URL:
        raise RecurringAuthorizationError("Solana RPC is not configured.")
    return Client(settings.X402_SOLANA_RPC_URL)


def load_recurring_delegation(address: str) -> RecurringDelegation:
    response = _rpc().get_account_info(Pubkey.from_string(address), encoding="base64")
    value = response.value
    if value is None:
        raise RecurringAuthorizationError("Recurring delegation not found.")
    if str(value.owner) != settings.X402_SOLANA_SUBSCRIPTIONS_PROGRAM:
        raise RecurringAuthorizationError("Recurring delegation owner is invalid.")
    return parse_recurring_delegation(address, bytes(value.data))


def _signer_keypair() -> Keypair:
    if not settings.X402_SOLANA_SIGNER_PRIVATE_KEY:
        raise RecurringAuthorizationError("Solana recurring signer is not configured.")
    try:
        return Keypair.from_base58_string(settings.X402_SOLANA_SIGNER_PRIVATE_KEY)
    except Exception as exc:
        raise RecurringAuthorizationError("Solana recurring signer is invalid.") from exc


def validate_delegation(delegation: RecurringDelegation) -> None:
    signer = _signer_keypair()
    if delegation.delegatee != str(signer.pubkey()):
        raise RecurringAuthorizationError("Recurring delegation delegatee is invalid.")
    if delegation.mint != settings.X402_SOLANA_ASSET:
        raise RecurringAuthorizationError("Recurring delegation asset is invalid.")
    if delegation.period_seconds != PERIOD_SECONDS:
        raise RecurringAuthorizationError("Recurring delegation period is invalid.")
    if delegation.expiry_ts == 0 or delegation.expiry_ts <= int(timezone.now().timestamp()):
        raise RecurringAuthorizationError("Recurring delegation is expired.")


def available_on_chain(delegation: RecurringDelegation) -> int:
    validate_delegation(delegation)
    period_ends_at = delegation.current_period_start_ts + delegation.period_seconds
    pulled = 0 if int(timezone.now().timestamp()) >= period_ends_at else delegation.amount_pulled_in_period
    return max(0, delegation.amount_per_period - pulled)


def available_amount(delegation: RecurringDelegation) -> int:
    reserved = (
        X402Authorization.objects.filter(
            status__in=[X402Authorization.Status.VERIFIED, X402Authorization.Status.SETTLING],
            valid_before__gt=timezone.now(),
            payment_payload__payload__authorizationProfile=PROFILE,
            payment_payload__payload__delegation=delegation.address,
        )
        .annotate(value_decimal=Cast("value", DecimalField(max_digits=78, decimal_places=0)))
        .aggregate(total=Sum("value_decimal"))["total"]
        or 0
    )
    return max(0, available_on_chain(delegation) - int(reserved))


def payment_identity(payload: dict[str, Any], network: str, max_timeout_seconds: int):
    delegation, request_nonce = recurring_payload_fields(payload)
    now = timezone.now()
    return {
        "nonce": recurring_nonce(network, delegation, request_nonce),
        "payer": load_recurring_delegation(delegation).wallet,
        "signature": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "valid_after": now,
        "valid_before": now + timedelta(seconds=max_timeout_seconds),
        "delegation": delegation,
    }


def verify_recurring(
    payload: dict[str, Any], amount: int, *, include_reservations: bool = True
) -> tuple[RecurringDelegation, int]:
    delegation_address, _ = recurring_payload_fields(payload)
    delegation = load_recurring_delegation(delegation_address)
    available = available_amount(delegation) if include_reservations else available_on_chain(delegation)
    if amount <= 0 or amount > available:
        raise RecurringAuthorizationError("Recurring delegation allowance is insufficient.")
    return delegation, available


def derive_ata(owner: str, mint: str) -> str:
    associated_token_program = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    address, _ = Pubkey.find_program_address(
        [
            bytes(Pubkey.from_string(owner)),
            bytes(Pubkey.from_string(settings.X402_SOLANA_TOKEN_PROGRAM)),
            bytes(Pubkey.from_string(mint)),
        ],
        associated_token_program,
    )
    return str(address)


def build_transfer_transaction(delegation: RecurringDelegation, amount: int) -> tuple[str, str]:
    validate_delegation(delegation)
    if amount <= 0:
        raise RecurringAuthorizationError("Settlement amount must be positive.")
    signer = _signer_keypair()
    program = Pubkey.from_string(settings.X402_SOLANA_SUBSCRIPTIONS_PROGRAM)
    mint = Pubkey.from_string(delegation.mint)
    source = Pubkey.from_string(derive_ata(delegation.wallet, delegation.mint))
    receiver = Pubkey.from_string(derive_ata(settings.X402_SOLANA_PAY_TO, delegation.mint))
    event_authority, _ = Pubkey.find_program_address([b"event_authority"], program)
    instruction = Instruction(
        program,
        bytes([5]) + struct.pack("<Q", amount) + bytes(Pubkey.from_string(delegation.wallet)) + bytes(mint),
        [
            AccountMeta(Pubkey.from_string(delegation.address), False, True),
            AccountMeta(Pubkey.from_string(delegation.subscription_authority), False, False),
            AccountMeta(source, False, True),
            AccountMeta(receiver, False, True),
            AccountMeta(mint, False, False),
            AccountMeta(Pubkey.from_string(settings.X402_SOLANA_TOKEN_PROGRAM), False, False),
            AccountMeta(signer.pubkey(), True, False),
            AccountMeta(event_authority, False, False),
            AccountMeta(program, False, False),
        ],
    )
    latest = _rpc().get_latest_blockhash().value
    message = MessageV0.try_compile(signer.pubkey(), [instruction], [], latest.blockhash)
    transaction = VersionedTransaction(message, [signer])
    signature = str(transaction.signatures[0])
    return signature, base64.b64encode(bytes(transaction)).decode()


def send_prepared(transaction_base64: str) -> str:
    transaction = VersionedTransaction.from_bytes(base64.b64decode(transaction_base64))
    expected = str(transaction.signatures[0])
    response = _rpc().send_raw_transaction(bytes(transaction))
    submitted = str(response.value)
    if submitted != expected:
        raise RecurringAuthorizationError("RPC returned a different recurring settlement signature.")
    return submitted


def transaction_status(signature: str) -> str:
    response = _rpc().get_signature_statuses([Signature.from_string(signature)])
    if not response.value or response.value[0] is None:
        return "pending"
    value = response.value[0]
    if value.err:
        return "failed"
    confirmed = value.confirmation_status and str(value.confirmation_status) in {"Confirmed", "Finalized"}
    return "confirmed" if confirmed else "pending"
