import hashlib
import secrets
import zlib
from contextlib import contextmanager
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
from x402.schemas import SettleRequest, SettleResponse, VerifyRequest, VerifyResponse

from x402f.models import X402Authorization
from x402f.official import BASE_MAINNET, build_configured_facilitator

RequestModel = TypeVar("RequestModel", bound=BaseModel)


@contextmanager
def _signer_lock(network: str):
    if connection.vendor != "postgresql":
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


def _seed_signer_nonce(signer) -> None:  # noqa: ANN001
    highest = X402Authorization.objects.filter(
        status=X402Authorization.Status.SETTLING,
        signer_nonce__isnull=False,
    ).aggregate(value=Max("signer_nonce"))["value"]
    if highest is not None:
        signer._next_nonce = int(highest) + 1


def _response(model: BaseModel, status_code: int = status.HTTP_200_OK) -> Response:
    return Response(model.model_dump(mode="json", by_alias=True, exclude_none=True), status=status_code)


def _parse_request(data: dict, model: type[RequestModel]) -> RequestModel:
    parsed = model.model_validate(data)
    if parsed.x402_version != 2 or parsed.payment_payload.x402_version != 2:
        raise ValueError("Only x402Version 2 is supported")
    return parsed


def _invalid_verify(reason: str) -> Response:
    return _response(VerifyResponse(is_valid=False, invalid_reason=reason))


def _failed_settle(reason: str, transaction_hash: str = "") -> Response:
    return _response(
        SettleResponse(
            success=False,
            error_reason=reason,
            transaction=transaction_hash,
            network=BASE_MAINNET,
        )
    )


def _authorization_data(request_model: VerifyRequest | SettleRequest) -> tuple[dict, str, str]:
    raw_payload = request_model.payment_payload.payload
    if "permit2Authorization" in raw_payload or "permit2_authorization" in raw_payload:
        raise ValueError("Only EIP-3009 exact authorization is supported")
    authorization = raw_payload.get("authorization")
    signature = raw_payload.get("signature")
    if not isinstance(authorization, dict) or not authorization.get("nonce") or not signature:
        raise ValueError("Only EIP-3009 exact authorization is supported")
    nonce = str(authorization["nonce"]).lower()
    if not nonce.startswith("0x") or len(nonce) != 66:
        raise ValueError("EIP-3009 nonce must be a 32-byte hex value")
    try:
        bytes.fromhex(nonce[2:])
    except ValueError as exc:
        raise ValueError("EIP-3009 nonce must be a 32-byte hex value") from exc
    requirements = request_model.payment_requirements
    payer = str(authorization.get("from", "")).lower()
    nonce_key = hashlib.sha256(
        f"{requirements.network}:{requirements.asset.lower()}:{payer}:{nonce}".encode()
    ).hexdigest()
    return authorization, nonce_key, str(signature)


def _validate_policy(request_model: VerifyRequest | SettleRequest) -> None:
    requirements = request_model.payment_requirements
    if str(requirements.network) != BASE_MAINNET or requirements.scheme != "exact":
        raise ValueError("Unsupported payment kind")
    if requirements.asset.lower() != settings.X402_BASE_ASSET.lower():
        raise ValueError("Unsupported payment asset")
    if not settings.X402_BASE_PAY_TO or requirements.pay_to.lower() != settings.X402_BASE_PAY_TO.lower():
        raise ValueError("Unsupported payment recipient")


class X402SupportedView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def get(self, request, *args, **kwargs):  # noqa: ANN001
        try:
            facilitator, _signer = build_configured_facilitator()
            return _response(facilitator.get_supported())
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
            authorization, nonce, signature = _authorization_data(verify_request)
        except (ValidationError, ValueError) as exc:
            return _invalid_verify(str(exc))

        try:
            facilitator, _signer = build_configured_facilitator()
            result = facilitator.verify(
                verify_request.payment_payload,
                verify_request.payment_requirements,
            )
        except Exception as exc:
            logger.error("official x402 verify failed: {}", exc)
            return _invalid_verify("Facilitator verification failed.")
        if not result.is_valid:
            return _response(result)

        requirements = verify_request.payment_requirements
        try:
            with transaction.atomic():
                X402Authorization.objects.create(
                    nonce=nonce,
                    payer=result.payer or authorization["from"],
                    pay_to=requirements.pay_to,
                    value=requirements.amount,
                    valid_after=datetime.fromtimestamp(int(authorization["validAfter"]), tz=datetime_timezone.utc),
                    valid_before=datetime.fromtimestamp(int(authorization["validBefore"]), tz=datetime_timezone.utc),
                    signature=signature,
                    payment_requirements=requirements.model_dump(mode="json", by_alias=True),
                    payment_payload=verify_request.payment_payload.model_dump(mode="json", by_alias=True),
                    scheme=requirements.scheme,
                )
        except IntegrityError:
            return _invalid_verify("Authorization nonce already processed.")
        except Exception as exc:
            logger.error("official x402 reservation failed: nonce={} error={}", nonce, exc)
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
            _authorization, nonce, _signature = _authorization_data(settle_request)
        except (ValidationError, ValueError) as exc:
            return _failed_settle(str(exc))

        try:
            record = X402Authorization.objects.get(nonce=nonce)
        except X402Authorization.DoesNotExist:
            return _failed_settle("Payment authorization was not verified.")
        except Exception as exc:
            logger.error("official x402 settlement load failed: nonce={} error={}", nonce, exc)
            return Response(
                _failed_settle("Unable to load payment authorization.").data,
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        incoming_requirements = settle_request.payment_requirements.model_dump(mode="json", by_alias=True)
        incoming_payload = settle_request.payment_payload.model_dump(mode="json", by_alias=True)
        if incoming_requirements != record.payment_requirements or incoming_payload != record.payment_payload:
            return _failed_settle("Payment payload or requirements do not match verification.")
        if record.status == X402Authorization.Status.SETTLED:
            return _response(
                SettleResponse(
                    success=True,
                    payer=record.payer,
                    transaction=record.transaction_hash or "",
                    network=BASE_MAINNET,
                    amount=record.value,
                )
            )

        if record.transaction_hash:
            try:
                _facilitator, signer = build_configured_facilitator()
                transaction_status = signer.get_transaction_status(record.transaction_hash)
            except Exception as exc:
                logger.error("official x402 reconciliation failed: nonce={} error={}", nonce, exc)
                return _failed_settle("Settlement transaction status is unavailable.", record.transaction_hash)
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
                        nonce,
                        record.transaction_hash,
                        exc,
                    )
                return _response(
                    SettleResponse(
                        success=True,
                        payer=record.payer,
                        transaction=record.transaction_hash,
                        network=BASE_MAINNET,
                        amount=record.value,
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
                    transaction_broadcast_at=None,
                    settling_started_at=None,
                )
                if cleared != 1:
                    return _failed_settle("Settlement state changed; retry.", record.transaction_hash)
                return _failed_settle("Settlement transaction failed on-chain.", record.transaction_hash)
            if record.prepared_transaction:
                try:
                    with _signer_lock(BASE_MAINNET):
                        _facilitator, signer = build_configured_facilitator()
                        _seed_signer_nonce(signer)
                        signer.broadcast_prepared(record.prepared_transaction)
                except Exception as exc:
                    logger.warning(
                        "official x402 prepared transaction rebroadcast failed: nonce={} error={}",
                        nonce,
                        exc,
                    )
            return _failed_settle("Settlement transaction is pending confirmation.", record.transaction_hash)

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
            return _failed_settle("Settlement is already in progress.")

        def persist_prepared_hash(tx_hash: str, raw_transaction: str, signer_nonce: int) -> None:
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
            with _signer_lock(BASE_MAINNET):
                facilitator, signer = build_configured_facilitator(persist_prepared_hash, mark_broadcast)
                _seed_signer_nonce(signer)
                result = facilitator.settle(
                    settle_request.payment_payload,
                    settle_request.payment_requirements,
                )
        except Exception as exc:
            logger.error("official x402 settlement failed: nonce={} error={}", nonce, exc)
            if record.transaction_hash is None:
                X402Authorization.objects.filter(
                    pk=record.pk,
                    status=X402Authorization.Status.SETTLING,
                    transaction_hash__isnull=True,
                    settling_started_at=claim_started_at,
                ).update(status=X402Authorization.Status.VERIFIED, settling_started_at=None)
            return _failed_settle("Facilitator settlement failed.", record.transaction_hash or "")

        if result.success:
            try:
                X402Authorization.objects.filter(pk=record.pk).update(
                    status=X402Authorization.Status.SETTLED,
                    transaction_hash=result.transaction,
                    settled_at=timezone.now(),
                    settling_started_at=None,
                )
            except Exception as exc:
                logger.error(
                    "successful x402 settlement final-state persistence failed: nonce={} tx={} error={}",
                    nonce,
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
