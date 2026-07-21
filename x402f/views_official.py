import hashlib
import json
import secrets
import threading
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone
from typing import TypeVar

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import Max, Q
from django.utils import timezone
from loguru import logger
from pydantic import BaseModel, ValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from x402.mechanisms.svm.constants import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from x402.mechanisms.svm.types import ExactSvmPayload
from x402.mechanisms.svm.utils import (
    decode_transaction_from_payload,
    get_token_payer_from_transaction,
    transaction_message_hash,
)
from x402.schemas import SettleRequest, SettleResponse, VerifyRequest, VerifyResponse

from x402f.models import X402Authorization
from x402f.official import (
    SKALE_MAINNET,
    ConfiguredFacilitator,
    build_configured_facilitator,
    configured_base_network,
    configured_supported_response,
)

RequestModel = TypeVar("RequestModel", bound=BaseModel)
_local_signer_locks: dict[str, threading.Lock] = {}
_local_signer_locks_guard = threading.Lock()


@dataclass(frozen=True)
class PaymentIdentity:
    nonce: str
    payer: str
    signature: str
    valid_after: datetime
    valid_before: datetime


@dataclass(frozen=True)
class RailPolicy:
    schemes: frozenset[str]
    asset: str
    pay_to: str


@contextmanager
def _signer_lock(network: str):
    if connection.vendor != "postgresql":
        with _local_signer_locks_guard:
            local_lock = _local_signer_locks.setdefault(network, threading.Lock())
        with local_lock:
            yield
        return
    lock_id = zlib.crc32(f"x402:{network}:signer".encode())
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_lock(%s)", [lock_id])
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s)", [lock_id])


def _seed_signer_nonce(signer, network: str) -> None:  # noqa: ANN001
    if not hasattr(signer, "_reserve_nonce"):
        return
    highest = X402Authorization.objects.filter(
        status=X402Authorization.Status.SETTLING,
        signer_nonce__isnull=False,
        payment_requirements__network=network,
    ).aggregate(value=Max("signer_nonce"))["value"]
    if highest is not None:
        signer._next_nonce = int(highest) + 1


def _transaction_status(signer, transaction_hash: str, network: str) -> str:  # noqa: ANN001
    if network.startswith("solana:"):
        return signer.get_transaction_status(transaction_hash, network)
    return signer.get_transaction_status(transaction_hash)


def _broadcast_prepared(signer, transaction: str, network: str) -> str:  # noqa: ANN001
    if network.startswith("solana:"):
        return signer.broadcast_prepared(transaction, network)
    return signer.broadcast_prepared(transaction)


def _configured(
    network: str,
    on_transaction_prepared=None,  # noqa: ANN001
    on_transaction_broadcast=None,  # noqa: ANN001
) -> ConfiguredFacilitator:
    facilitator, default_signer = build_configured_facilitator(
        on_transaction_prepared,
        on_transaction_broadcast,
        network,
    )
    signers = getattr(facilitator, "_acedata_signers", {configured_base_network(): default_signer})
    return ConfiguredFacilitator(facilitator, signers)


def _response(model: BaseModel, status_code: int = status.HTTP_200_OK) -> Response:
    return Response(model.model_dump(mode="json", by_alias=True, exclude_none=True), status=status_code)


def _parse_request(data: dict, model: type[RequestModel]) -> RequestModel:
    parsed = model.model_validate(data)
    if parsed.x402_version != 2 or parsed.payment_payload.x402_version != 2:
        raise ValueError("Only x402Version 2 is supported")
    return parsed


def _invalid_verify(reason: str) -> Response:
    return _response(VerifyResponse(is_valid=False, invalid_reason=reason))


def _failed_settle(reason: str, transaction_hash: str = "", network: str | None = None) -> Response:
    return _response(
        SettleResponse(
            success=False,
            error_reason=reason,
            transaction=transaction_hash,
            network=network or configured_base_network(),
        )
    )


def _canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _payment_identity(request_model: VerifyRequest | SettleRequest) -> PaymentIdentity:
    raw_payload = request_model.payment_payload.payload
    requirements = request_model.payment_requirements
    network = str(requirements.network)
    scheme = str(requirements.scheme)
    signature = str(raw_payload.get("signature") or "")

    if network.startswith("solana:"):
        svm_payload = ExactSvmPayload.from_dict(raw_payload)
        transaction = decode_transaction_from_payload(svm_payload)
        message_hash = transaction_message_hash(transaction)
        now = timezone.now()
        return PaymentIdentity(
            nonce=f"svm:{network}:{message_hash}",
            payer=get_token_payer_from_transaction(transaction),
            signature=hashlib.sha256(_canonical_json(raw_payload).encode()).hexdigest(),
            valid_after=now,
            valid_before=now + timedelta(seconds=requirements.max_timeout_seconds),
        )

    permit2 = raw_payload.get("permit2Authorization") or raw_payload.get("permit2_authorization")
    if permit2 is not None:
        if scheme != "upto" or not isinstance(permit2, dict):
            raise ValueError("Only EIP-3009 exact authorization is supported")
        payer = str(permit2.get("from") or "").lower()
        nonce = str(permit2.get("nonce") or "")
        witness = permit2.get("witness") or {}
        if not payer or not nonce or not signature or not isinstance(witness, dict):
            raise ValueError("Upto Permit2 authorization is incomplete")
        nonce_key = hashlib.sha256(
            f"{scheme}:{network}:{requirements.asset.lower()}:{payer}:{nonce}".encode()
        ).hexdigest()
        return PaymentIdentity(
            nonce=nonce_key,
            payer=payer,
            signature=signature,
            valid_after=datetime.fromtimestamp(int(witness.get("validAfter", 0)), tz=datetime_timezone.utc),
            valid_before=datetime.fromtimestamp(int(permit2.get("deadline", 0)), tz=datetime_timezone.utc),
        )

    authorization = raw_payload.get("authorization")
    if not isinstance(authorization, dict) or not authorization.get("nonce") or not signature:
        raise ValueError("Only EIP-3009 exact authorization is supported")
    nonce = str(authorization["nonce"]).lower()
    if not nonce.startswith("0x") or len(nonce) != 66:
        raise ValueError("EIP-3009 nonce must be a 32-byte hex value")
    try:
        bytes.fromhex(nonce[2:])
    except ValueError as exc:
        raise ValueError("EIP-3009 nonce must be a 32-byte hex value") from exc
    payer = str(authorization.get("from", "")).lower()
    nonce_key = hashlib.sha256(
        f"{requirements.network}:{requirements.asset.lower()}:{payer}:{nonce}".encode()
    ).hexdigest()
    return PaymentIdentity(
        nonce=nonce_key,
        payer=payer,
        signature=signature,
        valid_after=datetime.fromtimestamp(int(authorization["validAfter"]), tz=datetime_timezone.utc),
        valid_before=datetime.fromtimestamp(int(authorization["validBefore"]), tz=datetime_timezone.utc),
    )


def _rail_policy(network: str) -> RailPolicy:
    policies = {
        settings.X402_BASE_NETWORK: RailPolicy(
            schemes=frozenset(
                scheme
                for scheme, enabled in (
                    ("exact", settings.X402_BASE_EXACT_ENABLED),
                    ("upto", settings.X402_BASE_UPTO_ENABLED),
                )
                if enabled
            ),
            asset=settings.X402_BASE_ASSET,
            pay_to=settings.X402_BASE_PAY_TO,
        ),
        SKALE_MAINNET: RailPolicy(
            schemes=frozenset({"exact"}) if settings.X402_SKALE_EXACT_ENABLED else frozenset(),
            asset=settings.X402_SKALE_ASSET,
            pay_to=settings.X402_SKALE_PAY_TO,
        ),
        SOLANA_MAINNET_CAIP2: RailPolicy(
            schemes=frozenset({"exact"}) if settings.X402_SOLANA_MAINNET_ENABLED else frozenset(),
            asset=settings.X402_SOLANA_ASSET,
            pay_to=settings.X402_SOLANA_PAY_TO,
        ),
        SOLANA_DEVNET_CAIP2: RailPolicy(
            schemes=frozenset({"exact"}) if settings.X402_SOLANA_DEVNET_ENABLED else frozenset(),
            asset=settings.X402_SOLANA_DEVNET_ASSET,
            pay_to=settings.X402_SOLANA_DEVNET_PAY_TO,
        ),
    }
    try:
        return policies[network]
    except KeyError as exc:
        raise ValueError("Unsupported payment network") from exc


def _validate_policy(request_model: VerifyRequest | SettleRequest) -> None:
    requirements = request_model.payment_requirements
    network = str(requirements.network)
    policy = _rail_policy(network)
    if requirements.scheme not in policy.schemes:
        raise ValueError("Unsupported payment kind")
    asset_matches = (
        requirements.asset == policy.asset
        if network.startswith("solana:")
        else requirements.asset.lower() == policy.asset.lower()
    )
    pay_to_matches = (
        requirements.pay_to == policy.pay_to
        if network.startswith("solana:")
        else requirements.pay_to.lower() == policy.pay_to.lower()
    )
    if not asset_matches:
        raise ValueError("Unsupported payment asset")
    if not policy.pay_to or not pay_to_matches:
        raise ValueError("Unsupported payment recipient")


def _settlement_requirements_match(record: X402Authorization, incoming: dict) -> tuple[bool, str]:
    stored = record.payment_requirements
    if record.scheme != "upto":
        return incoming == stored, str(incoming.get("amount", record.value))
    incoming_without_amount = {key: value for key, value in incoming.items() if key != "amount"}
    stored_without_amount = {key: value for key, value in stored.items() if key != "amount"}
    amount = str(incoming.get("amount", ""))
    if (
        incoming_without_amount != stored_without_amount
        or not amount.isdigit()
        or not str(record.value).isdigit()
        or int(amount) > int(record.value)
    ):
        return False, amount
    return True, amount


class X402SupportedView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def get(self, request, *args, **kwargs):  # noqa: ANN001
        try:
            return _response(configured_supported_response())
        except Exception as exc:
            logger.error("official x402 supported failed: {}", exc)
            return Response({"error": "Facilitator is not configured."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class X402VerifyView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):  # noqa: ANN001
        try:
            verify_request = _parse_request(request.data, VerifyRequest)
            _validate_policy(verify_request)
            identity = _payment_identity(verify_request)
        except (ValidationError, ValueError) as exc:
            return _invalid_verify(str(exc))

        requirements = verify_request.payment_requirements
        verification_id = request.headers.get("X-Idempotency-Key", "").strip()
        if len(verification_id) > 128:
            return _invalid_verify("X-Idempotency-Key is too long.")
        serialized_requirements = requirements.model_dump(mode="json", by_alias=True)
        serialized_payload = verify_request.payment_payload.model_dump(mode="json", by_alias=True)
        existing = X402Authorization.objects.filter(nonce=identity.nonce).first()
        if existing is not None:
            if (
                existing.status == X402Authorization.Status.VERIFIED
                and bool(verification_id)
                and existing.verification_id == verification_id
                and existing.payment_requirements == serialized_requirements
                and existing.payment_payload == serialized_payload
                and existing.signature == identity.signature
            ):
                try:
                    configured = _configured(str(requirements.network))
                    result = configured.facilitator.verify(
                        verify_request.payment_payload,
                        verify_request.payment_requirements,
                    )
                except Exception:
                    return _invalid_verify("Unable to revalidate reserved payment authorization.")
                return _response(result)
            return _invalid_verify("Authorization nonce conflicts with a different payment.")

        try:
            configured = _configured(str(requirements.network))
            result = configured.facilitator.verify(
                verify_request.payment_payload,
                verify_request.payment_requirements,
            )
        except Exception as exc:
            logger.error("official x402 verify failed: {}", exc)
            return _invalid_verify("Facilitator verification failed.")
        if not result.is_valid:
            return _response(result)

        try:
            with transaction.atomic():
                X402Authorization.objects.create(
                    nonce=identity.nonce,
                    verification_id=verification_id or None,
                    payer=result.payer or identity.payer,
                    pay_to=requirements.pay_to,
                    value=requirements.amount,
                    valid_after=identity.valid_after,
                    valid_before=identity.valid_before,
                    signature=identity.signature,
                    payment_requirements=serialized_requirements,
                    payment_payload=serialized_payload,
                    scheme=requirements.scheme,
                )
        except IntegrityError:
            existing = X402Authorization.objects.filter(nonce=identity.nonce).first()
            if (
                existing is not None
                and existing.status == X402Authorization.Status.VERIFIED
                and bool(verification_id)
                and existing.verification_id == verification_id
                and existing.payment_requirements == serialized_requirements
                and existing.payment_payload == serialized_payload
                and existing.signature == identity.signature
            ):
                return _response(result)
            return _invalid_verify("Authorization nonce conflicts with a different payment.")
        except Exception as exc:
            logger.error("official x402 reservation failed: nonce={} error={}", identity.nonce, exc)
            return Response(
                VerifyResponse(
                    is_valid=False,
                    invalid_reason="Unable to reserve payment authorization.",
                ).model_dump(mode="json", by_alias=True, exclude_none=True),
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return _response(result)


class X402SettleView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):  # noqa: ANN001
        expected_token = settings.X402_SETTLE_TOKEN
        supplied_token = request.headers.get("X-Settlement-Token", "")
        if not expected_token or not supplied_token or not secrets.compare_digest(supplied_token, expected_token):
            return Response(
                {"success": False, "errorReason": "Unauthorized settlement caller."},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            settle_request = _parse_request(request.data, SettleRequest)
            _validate_policy(settle_request)
            identity = _payment_identity(settle_request)
        except (ValidationError, ValueError) as exc:
            return _failed_settle(str(exc))

        try:
            record = X402Authorization.objects.get(nonce=identity.nonce)
        except X402Authorization.DoesNotExist:
            return _failed_settle("Payment authorization was not verified.")
        except Exception as exc:
            logger.error("official x402 settlement load failed: nonce={} error={}", identity.nonce, exc)
            return Response(
                _failed_settle("Unable to load payment authorization.").data,
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        incoming_requirements = settle_request.payment_requirements.model_dump(mode="json", by_alias=True)
        incoming_payload = settle_request.payment_payload.model_dump(mode="json", by_alias=True)
        requirements_match, settled_amount = _settlement_requirements_match(record, incoming_requirements)
        network = str(incoming_requirements.get("network"))
        if not requirements_match or incoming_payload != record.payment_payload:
            return _failed_settle("Payment payload or requirements do not match verification.", network=network)
        if record.status == X402Authorization.Status.SETTLED:
            return _response(
                SettleResponse(
                    success=True,
                    payer=record.payer,
                    transaction=record.transaction_hash or "",
                    network=network,
                    amount=record.settled_amount or record.value,
                )
            )

        if record.transaction_hash:
            try:
                configured = _configured(network)
                signer = configured.signer_for(network)
                transaction_status = _transaction_status(signer, record.transaction_hash, network)
            except Exception as exc:
                logger.error("official x402 reconciliation failed: nonce={} error={}", identity.nonce, exc)
                return _failed_settle("Settlement transaction status is unavailable.", record.transaction_hash, network)
            if transaction_status == "confirmed":
                try:
                    X402Authorization.objects.filter(pk=record.pk).update(
                        status=X402Authorization.Status.SETTLED,
                        settled_at=timezone.now(),
                        settling_started_at=None,
                    )
                except Exception as exc:
                    logger.error(
                        "confirmed x402 settlement final-state persistence failed: nonce={} tx={} error={}",
                        identity.nonce,
                        record.transaction_hash,
                        exc,
                    )
                return _response(
                    SettleResponse(
                        success=True,
                        payer=record.payer,
                        transaction=record.transaction_hash,
                        network=network,
                        amount=record.settled_amount or record.value,
                    )
                )
            if transaction_status == "failed":
                cleared = X402Authorization.objects.filter(
                    pk=record.pk,
                    status=X402Authorization.Status.SETTLING,
                    transaction_hash=record.transaction_hash,
                ).update(
                    status=X402Authorization.Status.VERIFIED,
                    transaction_hash=None,
                    prepared_transaction=None,
                    signer_nonce=None,
                    settled_amount=None,
                    transaction_broadcast_at=None,
                    settling_started_at=None,
                )
                if cleared != 1:
                    return _failed_settle("Settlement state changed; retry.", record.transaction_hash, network)
                return _failed_settle("Settlement transaction failed on-chain.", record.transaction_hash, network)
            if record.prepared_transaction:
                try:
                    with _signer_lock(network):
                        configured = _configured(network)
                        signer = configured.signer_for(network)
                        _seed_signer_nonce(signer, network)
                        _broadcast_prepared(signer, record.prepared_transaction, network)
                except Exception as exc:
                    logger.warning(
                        "official x402 prepared transaction rebroadcast failed: nonce={} error={}",
                        identity.nonce,
                        exc,
                    )
            return _failed_settle("Settlement transaction is pending confirmation.", record.transaction_hash, network)

        lease_cutoff = timezone.now() - timedelta(seconds=settings.X402_SETTLEMENT_LEASE_SECONDS)
        claim_started_at = timezone.now()
        claimed = (
            X402Authorization.objects.filter(pk=record.pk, transaction_hash__isnull=True)
            .filter(
                Q(status=X402Authorization.Status.VERIFIED)
                | Q(status=X402Authorization.Status.SETTLING, settling_started_at__lt=lease_cutoff)
            )
            .update(status=X402Authorization.Status.SETTLING, settling_started_at=claim_started_at)
        )
        if claimed != 1:
            return _failed_settle("Settlement is already in progress.", network=network)
        if record.scheme == "upto":
            updated = X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                settling_started_at=claim_started_at,
            ).update(settled_amount=settled_amount)
            if updated != 1:
                return _failed_settle("Unable to persist upto settlement amount.", network=network)
            record.settled_amount = settled_amount

        def persist_prepared_hash(tx_hash: str, raw_transaction: str, signer_nonce: int | None) -> None:
            updated = X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                transaction_hash__isnull=True,
                settling_started_at=claim_started_at,
            ).update(
                transaction_hash=tx_hash,
                prepared_transaction=raw_transaction,
                signer_nonce=signer_nonce,
            )
            if updated != 1:
                raise RuntimeError("Unable to persist prepared settlement transaction hash")
            record.transaction_hash = tx_hash

        def mark_broadcast(tx_hash: str) -> None:
            updated = X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                transaction_hash=tx_hash,
            ).update(transaction_broadcast_at=timezone.now())
            if updated != 1:
                raise RuntimeError("Unable to persist settlement broadcast state")

        try:
            with _signer_lock(network):
                configured = _configured(network, persist_prepared_hash, mark_broadcast)
                signer = configured.signer_for(network)
                _seed_signer_nonce(signer, network)
                result = configured.facilitator.settle(
                    settle_request.payment_payload,
                    settle_request.payment_requirements,
                )
        except Exception as exc:
            logger.error("official x402 settlement failed: nonce={} error={}", identity.nonce, exc)
            if record.transaction_hash is None:
                X402Authorization.objects.filter(
                    pk=record.pk,
                    status=X402Authorization.Status.SETTLING,
                    transaction_hash__isnull=True,
                    settling_started_at=claim_started_at,
                ).update(status=X402Authorization.Status.VERIFIED, settling_started_at=None, settled_amount=None)
            return _failed_settle("Facilitator settlement failed.", record.transaction_hash or "", network)

        if result.success:
            try:
                X402Authorization.objects.filter(pk=record.pk).update(
                    status=X402Authorization.Status.SETTLED,
                    transaction_hash=result.transaction,
                    settled_amount=settled_amount,
                    settled_at=timezone.now(),
                    settling_started_at=None,
                )
            except Exception as exc:
                logger.error(
                    "successful x402 settlement final-state persistence failed: nonce={} tx={} error={}",
                    identity.nonce,
                    result.transaction or record.transaction_hash,
                    exc,
                )
        elif record.transaction_hash is None:
            X402Authorization.objects.filter(
                pk=record.pk,
                status=X402Authorization.Status.SETTLING,
                transaction_hash__isnull=True,
                settling_started_at=claim_started_at,
            ).update(status=X402Authorization.Status.VERIFIED, settling_started_at=None)
        elif not result.transaction:
            result = result.model_copy(update={"transaction": record.transaction_hash})
        return _response(result)
