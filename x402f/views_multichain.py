"""
Multi-chain X402 facilitator views using ChainHandler pattern.
"""

import secrets
import zlib
from contextlib import contextmanager
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone
from typing import Any, Dict

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import Q
from django.utils import timezone
from loguru import logger
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from x402f.chain_handlers import ChainHandlerFactory, SolanaExactHandler
from x402f.chain_handlers.base import TransactionStatus
from x402f.models import X402Authorization


class X402FacilitatorError(Exception):
    """Base error for x402 facilitator."""

    pass


class X402FacilitatorValidationError(X402FacilitatorError):
    """Validation error."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class X402SettlementPersistenceError(X402FacilitatorError):
    """A prepared transaction could not be recorded before broadcast."""

    pass


def _get_trace_id(request) -> str | None:  # noqa: ANN001
    return request.headers.get("X-Trace-ID")


@contextmanager
def _signer_lock(network: str):
    """Serialize one facilitator signer without holding a DB transaction."""
    if connection.vendor != "postgresql":
        yield
        return
    canonical_network = network.strip().lower()
    lock_id = zlib.crc32(f"x402:{canonical_network}:signer".encode("utf-8"))
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_lock(%s)", [lock_id])
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s)", [lock_id])


def _extract_signature(payload: Dict[str, Any]) -> str:
    raw_payload = payload.get("payload")
    if isinstance(raw_payload, dict):
        return payload.get("signature") or raw_payload.get("signature", "")
    return payload.get("signature", "")


def _extract_nonce(payload: Dict[str, Any], network: str) -> str | None:
    raw_payload = payload.get("payload")
    authorization = raw_payload.get("authorization") if isinstance(raw_payload, dict) else {}
    if isinstance(raw_payload, dict):
        # upto scheme stores nonce under permit2Authorization
        permit2 = raw_payload.get("permit2Authorization") or raw_payload.get("permit2_authorization") or {}
        nonce = raw_payload.get("nonce") or (authorization or {}).get("nonce") or permit2.get("nonce")
        if nonce:
            return str(nonce)
        tx_data = (
            raw_payload.get("serializedTransaction")
            or raw_payload.get("serialized_transaction")
            or raw_payload.get("transaction")
        )
        if isinstance(tx_data, dict) and tx_data.get("nonce"):
            return str(tx_data["nonce"])
        if isinstance(tx_data, str) and str(network).lower().startswith("solana"):
            return SolanaExactHandler.compute_transaction_nonce(tx_data)
    elif raw_payload and str(network).lower().startswith("solana"):
        return SolanaExactHandler.compute_transaction_nonce(str(raw_payload))

    signature = _extract_signature(payload)
    if signature:
        return f"{network}:{signature[:32]}"
    return None


def _summarize_requirements(requirements: Dict[str, Any]) -> Dict[str, Any]:
    extra = requirements.get("extra") or {}
    return {
        "network": requirements.get("network"),
        "payTo": requirements.get("payTo"),
        "asset": requirements.get("asset"),
        "maxAmountRequired": requirements.get("maxAmountRequired"),
        "amount": requirements.get("amount"),
        "chainId": extra.get("chainId"),
        "domainName": extra.get("name"),
        "domainVersion": extra.get("version"),
    }


def _summarize_payload(payload: Dict[str, Any], network: str) -> Dict[str, Any]:
    raw_payload = payload.get("payload")
    authorization = raw_payload.get("authorization") if isinstance(raw_payload, dict) else {}
    permit2 = raw_payload.get("permit2Authorization") if isinstance(raw_payload, dict) else None
    signature = _extract_signature(payload)
    summary = {
        "network": network,
        "scheme": payload.get("scheme"),
        "nonce": _extract_nonce(payload, network),
        "payloadType": type(raw_payload).__name__,
        "from": (authorization or {}).get("from"),
        "to": (authorization or {}).get("to"),
        "value": (authorization or {}).get("value"),
        "hasSignature": bool(signature),
        "signaturePrefix": signature[:16] if signature else None,
    }
    if isinstance(permit2, dict):
        summary["upto"] = {
            "from": permit2.get("from"),
            "permittedAmount": (permit2.get("permitted") or {}).get("amount"),
            "witnessTo": (permit2.get("witness") or {}).get("to"),
            "witnessFacilitator": (permit2.get("witness") or {}).get("facilitator"),
        }
    return summary


def _parse_payload(request_data: dict):
    """Parse payment payload and requirements from request data."""
    try:
        payload = request_data.get("paymentPayload", {})
        requirements = request_data.get("paymentRequirements", {})

        if not payload or not requirements:
            raise X402FacilitatorValidationError("Missing paymentPayload or paymentRequirements")

        return payload, requirements
    except Exception as exc:
        raise X402FacilitatorValidationError(f"Invalid request data: {exc}") from exc


def _get_chain_config(network: str) -> Dict[str, Any]:
    """
    Get chain-specific configuration from Django settings.

    For dynamic multi-chain support, configuration is keyed by network name.
    """
    # For Base chain
    network_lower = network.lower()
    if network_lower == "base":
        return {
            "rpc_url": getattr(settings, "X402_BASE_RPC_URL", ""),
            "signer_private_key": getattr(settings, "X402_BASE_SIGNER_PRIVATE_KEY", ""),
            "signer_address": getattr(settings, "X402_BASE_SIGNER_ADDRESS", ""),
            "fee_payer": getattr(settings, "X402_BASE_FEE_PAYER", ""),
            "gas_limit": getattr(settings, "X402_GAS_LIMIT", 250000),
            "chain_id": getattr(settings, "X402_BASE_CHAIN_ID", 8453),
            "tx_timeout_seconds": getattr(settings, "X402_TX_TIMEOUT_SECONDS", 120),
            "max_fee_per_gas_wei": getattr(settings, "X402_MAX_FEE_PER_GAS_WEI", 0),
            "max_priority_fee_per_gas_wei": getattr(settings, "X402_MAX_PRIORITY_FEE_PER_GAS_WEI", 0),
        }
    # For Solana chain (mainnet/devnet)
    elif network_lower in ("solana", "solana-devnet"):
        cluster = "devnet" if network_lower == "solana-devnet" else "mainnet-beta"
        return {
            "rpc_url": getattr(
                settings,
                "X402_SOLANA_RPC_URL",
                "https://api.devnet.solana.com" if cluster == "devnet" else "https://api.mainnet-beta.solana.com",
            ),
            "signer_private_key": getattr(settings, "X402_SOLANA_SIGNER_PRIVATE_KEY", ""),
            "signer_address": getattr(settings, "X402_SOLANA_SIGNER_ADDRESS", ""),
            "fee_payer": getattr(settings, "X402_SOLANA_FEE_PAYER", ""),
            "cluster": cluster,
        }
    # For SKALE Base chain (zero gas fees)
    elif network_lower == "skale":
        return {
            "rpc_url": getattr(settings, "X402_SKALE_RPC_URL", "https://skale-base.skalenodes.com/v1/base"),
            "signer_private_key": getattr(settings, "X402_SKALE_SIGNER_PRIVATE_KEY", ""),
            "signer_address": getattr(settings, "X402_SKALE_SIGNER_ADDRESS", ""),
            "fee_payer": getattr(settings, "X402_SKALE_FEE_PAYER", ""),
            "gas_limit": getattr(settings, "X402_SKALE_GAS_LIMIT", 50000000),
            "chain_id": getattr(settings, "X402_SKALE_CHAIN_ID", 1187947933),
            "tx_timeout_seconds": getattr(settings, "X402_TX_TIMEOUT_SECONDS", 120),
        }
    else:
        raise X402FacilitatorError(f"Unsupported network: {network}")


class X402SupportedView(APIView):
    """
    List supported payment kinds.

    Returns one entry per (network, scheme) tuple. For `upto`, includes
    `extra.facilitatorAddress` so clients can embed it in the witness.
    """

    authentication_classes: list = []
    permission_classes: list = []

    def get(self, request, *args, **kwargs):  # noqa: ANN001
        kinds: list[Dict[str, Any]] = []
        for network, scheme in ChainHandlerFactory.get_supported_kinds():
            entry: Dict[str, Any] = {"x402Version": 2, "scheme": scheme, "network": network}
            if scheme == "upto":
                # Surface the EOA the proxy will enforce as msg.sender.
                facilitator_address = getattr(settings, f"X402_{network.upper()}_SIGNER_ADDRESS", "") or getattr(
                    settings, "X402_SIGNER_ADDRESS", ""
                )
                if facilitator_address:
                    entry["extra"] = {
                        "facilitatorAddress": facilitator_address,
                        "chainId": _get_chain_config(network).get("chain_id"),
                    }
            kinds.append(entry)
        return Response({"kinds": kinds}, status=status.HTTP_200_OK)


class X402VerifyView(APIView):
    """
    Verify payment authorization signature.

    Supports multiple chains dynamically based on the network field
    in payment requirements.
    """

    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):
        trace_id = _get_trace_id(request)
        try:
            payload, requirements = _parse_payload(request.data)
        except X402FacilitatorValidationError as exc:
            logger.info("x402 verification failed: trace_id={} reason={}", trace_id, exc.message)
            return Response(
                {
                    "isValid": False,
                    "invalidReason": exc.message,
                    "payer": None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error("x402 verification misconfiguration: {}", exc)
            return Response(
                {
                    "isValid": False,
                    "invalidReason": "Facilitator misconfiguration.",
                    "payer": None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Get network + scheme from payload/requirements
        network = requirements.get("network", "base")
        scheme = payload.get("scheme") or requirements.get("scheme") or "exact"
        logger.debug(
            "x402 verification request: trace_id={} network={} scheme={} requirements={} payload={}",
            trace_id,
            network,
            scheme,
            _summarize_requirements(requirements),
            _summarize_payload(payload, network),
        )

        try:
            # Create chain handler for the (network, scheme) tuple
            config = _get_chain_config(network)
            handler = ChainHandlerFactory.create(network, config, scheme=scheme)

            # Verify signature using chain handler
            result = handler.verify_signature(payload, requirements)

            if not result.is_valid:
                logger.info(
                    "x402 verification failed: trace_id={} network={} nonce={} payer={} reason={} details={}",
                    trace_id,
                    network,
                    _extract_nonce(payload, network),
                    result.payer,
                    result.invalid_reason,
                    result.details,
                )
                return Response(
                    {
                        "isValid": False,
                        "invalidReason": result.invalid_reason,
                        "payer": result.payer,
                    },
                    status=status.HTTP_200_OK,
                )

            # Extract nonce and other data
            nonce = result.details.get("nonce") if result.details else payload.get("payload", {}).get("nonce")
            # Upto stores nonce under permit2Authorization
            if not nonce:
                permit2 = payload.get("payload", {}).get("permit2Authorization") or {}
                nonce = permit2.get("nonce")
            # Always capture signature (top-level or nested) for storage/fallback
            signature = payload.get("signature") or payload.get("payload", {}).get("signature", "")
            if not nonce:
                # Try to get from transaction data
                tx_data = payload.get("payload", {}).get("transaction", {})
                nonce = tx_data.get("nonce") if tx_data else None

            if not nonce:
                # Generate a unique identifier from signature
                nonce = f"{network}:{signature[:32]}"

            # Nonce uniqueness key: upto Permit2 nonces are 256-bit ints that may
            # collide across schemes; prefix with scheme to keep DB-unique.
            stored_nonce = f"{scheme}:{network}:{nonce}" if scheme != "exact" else str(nonce)

            # Store authorization record
            try:
                with transaction.atomic():
                    record = X402Authorization(
                        nonce=stored_nonce,
                        payer=result.payer,
                        pay_to=requirements.get("payTo", ""),
                        value=str(
                            (result.details or {}).get("permitted_amount") or (result.details or {}).get("amount", 0)
                        ),
                        valid_after=datetime.now(datetime_timezone.utc),  # Simplified
                        valid_before=datetime.now(datetime_timezone.utc),  # Simplified
                        signature=signature,
                        payment_requirements=requirements,
                        payment_payload=payload,
                        scheme=scheme,
                    )
                    record.save(force_insert=True)
            except IntegrityError:
                logger.info(
                    "x402 authorization replay detected: trace_id={} network={} nonce={} payer={}",
                    trace_id,
                    network,
                    nonce,
                    result.payer,
                )
                return Response(
                    {
                        "isValid": False,
                        "invalidReason": "Authorization nonce already processed.",
                        "payer": None,
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception as db_exc:
                logger.error(
                    "x402 failed to reserve authorization: trace_id={} network={} nonce={} payer={} error={}",
                    trace_id,
                    network,
                    nonce,
                    result.payer,
                    db_exc,
                )
                return Response(
                    {
                        "isValid": False,
                        "invalidReason": "Unable to reserve payment authorization.",
                        "payer": None,
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            logger.info(
                "x402 authorization stored: trace_id={} network={} nonce={} payer={} pay_to={} amount={} asset={}",
                trace_id,
                network,
                nonce,
                result.payer,
                requirements.get("payTo"),
                (result.details or {}).get("amount"),
                requirements.get("asset"),
            )

            return Response(
                {
                    "isValid": True,
                    "invalidReason": None,
                    "payer": result.payer,
                },
                status=status.HTTP_200_OK,
            )

        except ValueError as exc:
            # Unsupported network
            logger.error("x402 unsupported network: trace_id={} network={} {}", trace_id, network, exc)
            return Response(
                {
                    "isValid": False,
                    "invalidReason": f"Unsupported network: {network}",
                    "payer": None,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error("x402 verification error: trace_id={} network={} {}", trace_id, network, exc)
            import traceback

            logger.error(traceback.format_exc())
            return Response(
                {
                    "isValid": False,
                    "invalidReason": f"Verification error: {str(exc)}",
                    "payer": None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class X402SettleView(APIView):
    """
    Settle payment on-chain.

    Supports multiple chains dynamically based on the network field
    in payment requirements.
    """

    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs) -> Response:
        trace_id = _get_trace_id(request)
        try:
            payload, requirements = _parse_payload(request.data)
        except X402FacilitatorValidationError as exc:
            logger.info("x402 settlement validation failed: trace_id={} reason={}", trace_id, exc.message)
            return Response(
                {
                    "success": False,
                    "errorReason": exc.message,
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error("x402 settlement misconfiguration: {}", exc)
            return Response(
                {
                    "success": False,
                    "errorReason": "Facilitator misconfiguration.",
                    "transaction": None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Get network + scheme from payload/requirements
        network = requirements.get("network", "base")
        scheme = payload.get("scheme") or requirements.get("scheme") or "exact"
        # Exact authorizations bind the full amount/payee at verify time, so
        # public settlement cannot reduce or redirect payment. Upto settlement
        # carries the resource server's metered actual amount and therefore
        # requires authentication from the trusted Gateway.
        if scheme == "upto":
            expected_token = getattr(settings, "X402_SETTLE_TOKEN", "")
            supplied_token = request.headers.get("X-Settlement-Token", "")
            if not expected_token:
                logger.error("x402 upto settlement disabled: X402_SETTLE_TOKEN is not configured")
                return Response(
                    {
                        "success": False,
                        "errorReason": "Settlement authentication is not configured.",
                        "transaction": None,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            if not supplied_token or not secrets.compare_digest(supplied_token, expected_token):
                return Response(
                    {"success": False, "errorReason": "Unauthorized settlement caller.", "transaction": None},
                    status=status.HTTP_403_FORBIDDEN,
                )
        logger.debug(
            "x402 settlement request: trace_id={} network={} scheme={} requirements={} payload={}",
            trace_id,
            network,
            scheme,
            _summarize_requirements(requirements),
            _summarize_payload(payload, network),
        )

        signature = _extract_signature(payload)
        nonce = _extract_nonce(payload, network)
        if nonce is None:
            nonce = f"{network}:{(signature or '')[:32]}"

        # Mirror verify-time nonce prefixing so we can look up the right record.
        stored_nonce = f"{scheme}:{network}:{nonce}" if scheme != "exact" else str(nonce)
        claimed_record_id = None
        claim_started_at = None

        def release_unsubmitted_claim() -> None:
            if claimed_record_id is not None and claim_started_at is not None:
                X402Authorization.objects.filter(
                    pk=claimed_record_id,
                    status=X402Authorization.Status.SETTLING,
                    transaction_hash__isnull=True,
                    settling_started_at=claim_started_at,
                ).update(
                    status=X402Authorization.Status.VERIFIED,
                    settling_started_at=None,
                    settled_amount=None,
                )

        try:
            # Load the verify-time reservation. Settlement ownership is claimed
            # atomically below; never hold a database lock across chain RPC I/O.
            try:
                record = X402Authorization.objects.get(nonce=stored_nonce)
            except X402Authorization.DoesNotExist:
                logger.info(
                    "x402 settlement attempted without prior verification: trace_id={} network={} nonce={}",
                    trace_id,
                    network,
                    nonce,
                )
                return Response(
                    {"success": False, "errorReason": "Payment authorization was not verified.", "transaction": None},
                    status=status.HTTP_200_OK,
                )
            except Exception as db_exc:
                logger.error(
                    "x402 settle DB unavailable: trace_id={} network={} nonce={} error={}",
                    trace_id,
                    network,
                    nonce,
                    db_exc,
                )
                return Response(
                    {"success": False, "errorReason": "Unable to load payment authorization.", "transaction": None},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            stored_requirements = record.payment_requirements or {}
            for field in ("scheme", "network", "asset", "payTo"):
                stored_value = stored_requirements.get(field)
                incoming_value = requirements.get(field)
                if stored_value and incoming_value and str(stored_value).lower() != str(incoming_value).lower():
                    return Response(
                        {
                            "success": False,
                            "errorReason": f"Payment requirement mismatch: {field}",
                            "transaction": None,
                        },
                        status=status.HTTP_200_OK,
                    )

            incoming_amount = requirements.get("amount") or requirements.get("maxAmountRequired")
            stored_amount = stored_requirements.get("amount") or stored_requirements.get("maxAmountRequired")
            if scheme == "exact" and stored_amount is not None and str(incoming_amount) != str(stored_amount):
                return Response(
                    {
                        "success": False,
                        "errorReason": "Payment requirement mismatch: amount",
                        "transaction": None,
                    },
                    status=status.HTTP_200_OK,
                )
            if scheme == "upto" and incoming_amount is None:
                return Response(
                    {
                        "success": False,
                        "errorReason": "Missing settlement amount.",
                        "transaction": record.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )
            if (
                scheme == "upto"
                and record.settled_amount is not None
                and str(incoming_amount) != str(record.settled_amount)
            ):
                return Response(
                    {
                        "success": False,
                        "errorReason": "Payment requirement mismatch: settled amount",
                        "transaction": record.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )

            if record.status == X402Authorization.Status.SETTLED:
                logger.info(
                    "x402 settlement idempotent hit: trace_id={} network={} nonce={} tx={}",
                    trace_id,
                    network,
                    nonce,
                    record.transaction_hash,
                )
                return Response(
                    {
                        "success": True,
                        "errorReason": None,
                        "transaction": record.transaction_hash,
                        "network": network,
                        "payer": record.payer,
                    },
                    status=status.HTTP_200_OK,
                )
            if record.status == X402Authorization.Status.FAILED:
                return Response(
                    {
                        "success": False,
                        "errorReason": "Settlement transaction failed on-chain.",
                        "transaction": record.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )
            payload = record.payment_payload

            # Create chain handler
            config = _get_chain_config(network)
            handler = ChainHandlerFactory.create(network, config, scheme=scheme)

            if record.transaction_hash:
                observed_tx_hash = record.transaction_hash

                def reconciliation_conflict_response() -> Response:
                    record.refresh_from_db()
                    if record.status == X402Authorization.Status.SETTLED:
                        return Response(
                            {
                                "success": True,
                                "errorReason": None,
                                "transaction": record.transaction_hash,
                                "network": network,
                                "payer": record.payer,
                            },
                            status=status.HTTP_200_OK,
                        )
                    return Response(
                        {
                            "success": False,
                            "errorReason": "Settlement state changed; retry.",
                            "transaction": record.transaction_hash,
                        },
                        status=status.HTTP_200_OK,
                    )

                # Reconcile: if a previous settle attempt left a tx hash, check on-chain
                logger.debug(
                    "x402 settlement reconcile check: trace_id={} network={} nonce={} tx={}",
                    trace_id,
                    network,
                    nonce,
                    record.transaction_hash,
                )
                tx_status = handler.get_transaction_status(observed_tx_hash)
                if tx_status == TransactionStatus.CONFIRMED:
                    reconciled = X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        transaction_hash=observed_tx_hash,
                    ).update(
                        status=X402Authorization.Status.SETTLED,
                        settled_at=timezone.now(),
                        settling_started_at=None,
                        updated_at=timezone.now(),
                    )
                    if reconciled != 1:
                        return reconciliation_conflict_response()
                    logger.info(
                        "x402 settlement reconciled: trace_id={} network={} nonce={} tx={}",
                        trace_id,
                        network,
                        nonce,
                        observed_tx_hash,
                    )
                    return Response(
                        {
                            "success": True,
                            "errorReason": None,
                            "transaction": observed_tx_hash,
                            "network": network,
                            "payer": record.payer,
                        },
                        status=status.HTTP_200_OK,
                    )
                if tx_status == TransactionStatus.FAILED:
                    if str(network).lower().startswith("solana"):
                        reconciled = X402Authorization.objects.filter(
                            pk=record.pk,
                            status=X402Authorization.Status.SETTLING,
                            transaction_hash=observed_tx_hash,
                        ).update(
                            status=X402Authorization.Status.FAILED,
                            settling_started_at=None,
                        )
                    else:
                        reconciled = X402Authorization.objects.filter(
                            pk=record.pk,
                            status=X402Authorization.Status.SETTLING,
                            transaction_hash=observed_tx_hash,
                        ).update(
                            status=X402Authorization.Status.VERIFIED,
                            transaction_hash=None,
                            settling_started_at=None,
                            settled_amount=None,
                        )
                    if reconciled != 1:
                        return reconciliation_conflict_response()
                    return Response(
                        {
                            "success": False,
                            "errorReason": "Settlement transaction failed on-chain.",
                            "transaction": observed_tx_hash,
                        },
                        status=status.HTTP_200_OK,
                    )
                return Response(
                    {
                        "success": False,
                        "errorReason": "Settlement transaction is pending confirmation.",
                        "transaction": record.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )

            lease_seconds = int(getattr(settings, "X402_SETTLEMENT_LEASE_SECONDS", 300))
            lease_cutoff = timezone.now() - timedelta(seconds=lease_seconds)
            if (
                record.status == X402Authorization.Status.SETTLING
                and record.settling_started_at
                and record.settling_started_at >= lease_cutoff
            ):
                return Response(
                    {
                        "success": False,
                        "errorReason": "Settlement is already in progress.",
                        "transaction": None,
                    },
                    status=status.HTTP_200_OK,
                )

            claim_started_at = timezone.now()
            claim_updates = {
                "status": X402Authorization.Status.SETTLING,
                "settling_started_at": claim_started_at,
            }
            if scheme == "upto":
                claim_updates["settled_amount"] = str(incoming_amount)

            claimed = (
                X402Authorization.objects.filter(pk=record.pk, transaction_hash__isnull=True)
                .filter(
                    Q(status=X402Authorization.Status.VERIFIED)
                    | Q(
                        status=X402Authorization.Status.SETTLING,
                        settling_started_at__lt=lease_cutoff,
                    )
                )
                .update(**claim_updates)
            )
            if claimed != 1:
                record.refresh_from_db()
                if record.status == X402Authorization.Status.SETTLED:
                    return Response(
                        {
                            "success": True,
                            "errorReason": None,
                            "transaction": record.transaction_hash,
                            "network": network,
                            "payer": record.payer,
                        },
                        status=status.HTTP_200_OK,
                    )
                return Response(
                    {
                        "success": False,
                        "errorReason": "Settlement is already in progress.",
                        "transaction": record.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )
            record.status = X402Authorization.Status.SETTLING
            record.settling_started_at = claim_started_at
            if scheme == "upto":
                record.settled_amount = str(incoming_amount)
            claimed_record_id = record.pk

            def persist_prepared_hash(tx_hash: str) -> None:
                try:
                    updated = X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        transaction_hash__isnull=True,
                        settling_started_at=claim_started_at,
                    ).update(transaction_hash=tx_hash)
                except Exception as exc:
                    raise X402SettlementPersistenceError(
                        "Unable to persist prepared settlement transaction hash"
                    ) from exc
                if updated != 1:
                    raise X402SettlementPersistenceError("Unable to persist prepared settlement transaction hash")
                record.transaction_hash = tx_hash

            # Settle payment using chain handler
            with _signer_lock(network):
                result = handler.settle_payment(
                    payload,
                    requirements,
                    on_transaction_prepared=persist_prepared_hash,
                )

            if not result.success:
                if (result.details or {}).get("broadcast_status") == "rejected":
                    X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        settling_started_at=claim_started_at,
                    ).update(
                        status=X402Authorization.Status.FAILED,
                        transaction_hash=None,
                        settling_started_at=None,
                        settled_amount=None,
                    )
                    record.status = X402Authorization.Status.FAILED
                    record.transaction_hash = None
                    result.transaction_hash = None
                elif (result.details or {}).get("transaction_status") == "failed":
                    released = X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        transaction_hash=result.transaction_hash,
                        settling_started_at=claim_started_at,
                    ).update(
                        status=X402Authorization.Status.VERIFIED,
                        transaction_hash=None,
                        settling_started_at=None,
                        settled_amount=None,
                    )
                    if released == 1:
                        record.status = X402Authorization.Status.VERIFIED
                        record.transaction_hash = None
                # Persist tx hash for future reconciliation even on failure
                elif record and result.transaction_hash and not record.transaction_hash:
                    record.transaction_hash = result.transaction_hash
                    try:
                        record.save(update_fields=["status", "transaction_hash", "updated_at"])
                    except Exception:
                        pass
                elif record and not result.transaction_hash:
                    X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        transaction_hash__isnull=True,
                        settling_started_at=claim_started_at,
                    ).update(
                        status=X402Authorization.Status.VERIFIED,
                        settling_started_at=None,
                        settled_amount=None,
                    )

                logger.error(
                    "x402 settlement failed: trace_id={} network={} nonce={} payer={} reason={} "
                    "transaction={} details={}",
                    trace_id,
                    network,
                    nonce,
                    record.payer if record else result.payer,
                    result.error_reason,
                    result.transaction_hash,
                    result.details,
                )
                return Response(
                    {
                        "success": False,
                        "errorReason": result.error_reason,
                        "transaction": result.transaction_hash,
                    },
                    status=status.HTTP_200_OK,
                )

            # Mark as settled
            if record:
                settled_amount = (result.details or {}).get("amount")
                try:
                    settled = X402Authorization.objects.filter(
                        pk=record.pk,
                        status=X402Authorization.Status.SETTLING,
                        transaction_hash=result.transaction_hash,
                        settling_started_at=claim_started_at,
                    ).update(
                        status=X402Authorization.Status.SETTLED,
                        settled_at=timezone.now(),
                        settled_amount=str(settled_amount) if settled_amount is not None else None,
                        settling_started_at=None,
                        updated_at=timezone.now(),
                    )
                except Exception as save_exc:
                    logger.error("x402 settled but failed to persist result: {}", save_exc)
                    return Response(
                        {
                            "success": False,
                            "errorReason": "Settlement confirmed but result persistence failed.",
                            "transaction": result.transaction_hash,
                        },
                        status=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
                if settled != 1:
                    record.refresh_from_db()
                    if not (
                        record.status == X402Authorization.Status.SETTLED
                        and record.transaction_hash == result.transaction_hash
                    ):
                        return Response(
                            {
                                "success": False,
                                "errorReason": "Settlement confirmed but claim ownership changed.",
                                "transaction": result.transaction_hash,
                            },
                            status=status.HTTP_503_SERVICE_UNAVAILABLE,
                        )

            logger.info(
                "x402 settlement succeeded: trace_id={} network={} nonce={} tx={} payer={} amount={}",
                trace_id,
                network,
                nonce,
                result.transaction_hash,
                result.payer,
                (result.details or {}).get("amount"),
            )

            settled_amount = (result.details or {}).get("amount")
            return Response(
                {
                    "success": True,
                    "errorReason": None,
                    "transaction": result.transaction_hash,
                    "network": network,
                    "payer": result.payer,
                    "amount": str(settled_amount) if settled_amount is not None else None,
                },
                status=status.HTTP_200_OK,
            )

        except X402FacilitatorValidationError as exc:
            release_unsubmitted_claim()
            logger.info("x402 settlement rejected: trace_id={} reason={}", trace_id, exc.message)
            return Response(
                {
                    "success": False,
                    "errorReason": exc.message,
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except ValueError as exc:
            release_unsubmitted_claim()
            # Unsupported network
            logger.error("x402 unsupported network: trace_id={} network={} {}", trace_id, network, exc)
            return Response(
                {
                    "success": False,
                    "errorReason": f"Unsupported network: {network}",
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except X402SettlementPersistenceError as exc:
            release_unsubmitted_claim()
            logger.error(
                "x402 settlement persistence error: trace_id={} network={} nonce={} {}",
                trace_id,
                network,
                nonce,
                exc,
            )
            return Response(
                {
                    "success": False,
                    "errorReason": "Unable to persist prepared settlement transaction.",
                    "transaction": None,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as exc:
            release_unsubmitted_claim()
            logger.error("x402 settlement error: trace_id={} network={} nonce={} {}", trace_id, network, nonce, exc)
            import traceback

            logger.error(traceback.format_exc())
            return Response(
                {
                    "success": False,
                    "errorReason": f"Settlement error: {str(exc)}",
                    "transaction": None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
