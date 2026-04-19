"""
Multi-chain X402 facilitator views using ChainHandler pattern.
"""

import base64
import hashlib
from datetime import datetime
from datetime import timezone as datetime_timezone
from typing import Any, Dict

from django.conf import settings
from django.db import IntegrityError, transaction
from loguru import logger
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from x402f.chain_handlers import ChainHandlerFactory
from x402f.models import X402Authorization


class X402FacilitatorError(Exception):
    """Base error for x402 facilitator."""

    pass


class X402FacilitatorValidationError(X402FacilitatorError):
    """Validation error."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _get_trace_id(request) -> str | None:  # noqa: ANN001
    return request.headers.get("X-Trace-ID")


def _extract_signature(payload: Dict[str, Any]) -> str:
    raw_payload = payload.get("payload")
    if isinstance(raw_payload, dict):
        return payload.get("signature") or raw_payload.get("signature", "")
    return payload.get("signature", "")


def _extract_nonce(payload: Dict[str, Any], network: str) -> str | None:
    raw_payload = payload.get("payload")
    authorization = raw_payload.get("authorization") if isinstance(raw_payload, dict) else {}
    if isinstance(raw_payload, dict):
        nonce = raw_payload.get("nonce") or (authorization or {}).get("nonce")
        if nonce:
            return str(nonce)
        tx_data = (
            raw_payload.get("serializedTransaction")
            or raw_payload.get("serialized_transaction")
            or raw_payload.get("transaction")
        )
        if isinstance(tx_data, dict) and tx_data.get("nonce"):
            return str(tx_data["nonce"])
    elif raw_payload and str(network).lower().startswith("solana"):
        try:
            tx_bytes = base64.b64decode(raw_payload)
            digest = hashlib.sha256(tx_bytes).hexdigest()[:32]
            return f"solana:{digest}"
        except Exception:
            return None

    signature = _extract_signature(payload)
    if signature:
        return f"{network}:{signature[:16]}"
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
    signature = _extract_signature(payload)
    return {
        "network": network,
        "nonce": _extract_nonce(payload, network),
        "payloadType": type(raw_payload).__name__,
        "from": (authorization or {}).get("from"),
        "to": (authorization or {}).get("to"),
        "value": (authorization or {}).get("value"),
        "hasSignature": bool(signature),
        "signaturePrefix": signature[:16] if signature else None,
    }


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
            "tx_timeout_seconds": getattr(settings, "X402_TX_TIMEOUT_SECONDS", 120),
        }
    else:
        raise X402FacilitatorError(f"Unsupported network: {network}")


class X402SupportedView(APIView):
    """
    List supported payment kinds.

    Mirrors the CDP facilitator `/supported` shape:
    { "kinds": [ { "x402Version": 1, "scheme": "exact", "network": "base" }, ... ] }
    """

    authentication_classes: list = []
    permission_classes: list = []

    def get(self, request, *args, **kwargs):  # noqa: ANN001
        kinds = [
            {"x402Version": 2, "scheme": "exact", "network": network}
            for network in ChainHandlerFactory.get_supported_networks()
        ]
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

        # Get network from requirements
        network = requirements.get("network", "base")
        logger.debug(
            "x402 verification request: trace_id={} network={} requirements={} payload={}",
            trace_id,
            network,
            _summarize_requirements(requirements),
            _summarize_payload(payload, network),
        )

        try:
            # Create chain handler for the network
            config = _get_chain_config(network)
            handler = ChainHandlerFactory.create(network, config)

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
            # Always capture signature (top-level or nested) for storage/fallback
            signature = payload.get("signature") or payload.get("payload", {}).get("signature", "")
            if not nonce:
                # Try to get from transaction data
                tx_data = payload.get("payload", {}).get("transaction", {})
                nonce = tx_data.get("nonce") if tx_data else None

            if not nonce:
                # Generate a unique identifier from signature
                nonce = f"{network}:{signature[:32]}"

            # Store authorization record
            try:
                with transaction.atomic():
                    record = X402Authorization(
                        nonce=str(nonce),
                        payer=result.payer,
                        pay_to=requirements.get("payTo", ""),
                        value=str(result.details.get("amount", 0)) if result.details else "0",
                        valid_after=datetime.now(datetime_timezone.utc),  # Simplified
                        valid_before=datetime.now(datetime_timezone.utc),  # Simplified
                        signature=signature,
                        payment_requirements=requirements,
                        payment_payload=payload,
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
                logger.warning(
                    "x402 failed to store authorization record (non-fatal): trace_id={} network={} "
                    "nonce={} payer={} error={}",
                    trace_id,
                    network,
                    nonce,
                    result.payer,
                    db_exc,
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

        # Get network from requirements
        network = requirements.get("network", "base")
        logger.debug(
            "x402 settlement request: trace_id={} network={} requirements={} payload={}",
            trace_id,
            network,
            _summarize_requirements(requirements),
            _summarize_payload(payload, network),
        )

        # Extract nonce from payload, handling both EVM and Solana shapes
        raw_payload = payload.get("payload")
        signature = payload.get("signature") or (raw_payload.get("signature") if isinstance(raw_payload, dict) else "")

        nonce = None
        auth = raw_payload.get("authorization") if isinstance(raw_payload, dict) else {}
        if isinstance(raw_payload, dict):
            nonce = raw_payload.get("nonce") or (auth or {}).get("nonce")
            tx_data = (
                raw_payload.get("serializedTransaction")
                or raw_payload.get("serialized_transaction")
                or raw_payload.get("transaction")
            )
            if nonce is None and isinstance(tx_data, dict):
                nonce = tx_data.get("nonce")
        else:
            # raw_payload might be a base64 solana transaction string
            tx_data = raw_payload

        # For solana, derive nonce from first signature if not provided
        if nonce is None and str(network).lower().startswith("solana") and tx_data:
            try:
                tx_bytes = base64.b64decode(tx_data)
                digest = hashlib.sha256(tx_bytes).hexdigest()[:32]
                nonce = f"solana:{digest}"
            except Exception:
                nonce = None

        if nonce is None:
            nonce = f"{network}:{(signature or '')[:32]}"

        try:
            # Check if authorization exists and not settled
            record = None
            try:
                with transaction.atomic():
                    try:
                        record = X402Authorization.objects.select_for_update().get(nonce=str(nonce))
                    except X402Authorization.DoesNotExist:
                        logger.info(
                            "x402 settlement attempted without prior verification: trace_id={} network={} nonce={}",
                            trace_id,
                            network,
                            nonce,
                        )
                        # Don't fail — proceed without record (DB may have been down during verify)
            except Exception as db_exc:
                logger.warning(
                    "x402 settle DB unavailable (non-fatal), proceeding without record: trace_id={} "
                    "network={} nonce={} error={}",
                    trace_id,
                    network,
                    nonce,
                    db_exc,
                )
                pass  # db_available not needed, record stays None

            if record and record.status == X402Authorization.Status.SETTLED:
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

            # Create chain handler
            config = _get_chain_config(network)
            handler = ChainHandlerFactory.create(network, config)

            if record and record.transaction_hash:
                # Reconcile: if a previous settle attempt left a tx hash, check on-chain
                logger.debug(
                    "x402 settlement reconcile check: trace_id={} network={} nonce={} tx={}",
                    trace_id,
                    network,
                    nonce,
                    record.transaction_hash,
                )
                confirmed = handler.check_transaction_status(record.transaction_hash)
                if confirmed:
                    record.mark_settled(record.transaction_hash)
                    try:
                        record.save(update_fields=["status", "transaction_hash", "settled_at", "updated_at"])
                    except Exception:
                        pass
                    logger.info(
                        "x402 settlement reconciled: trace_id={} network={} nonce={} tx={}",
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

            # Settle payment using chain handler
            result = handler.settle_payment(payload, requirements)

            if not result.success:
                # Persist tx hash for future reconciliation even on failure
                if record and result.transaction_hash and not record.transaction_hash:
                    record.transaction_hash = result.transaction_hash
                    try:
                        record.save(update_fields=["transaction_hash", "updated_at"])
                    except Exception:
                        pass

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
                record.mark_settled(result.transaction_hash)
                try:
                    record.save(update_fields=["status", "transaction_hash", "settled_at", "updated_at"])
                except Exception:
                    pass

            logger.info(
                "x402 settlement succeeded: trace_id={} network={} nonce={} tx={} payer={}",
                trace_id,
                network,
                nonce,
                result.transaction_hash,
                result.payer,
            )

            return Response(
                {
                    "success": True,
                    "errorReason": None,
                    "transaction": result.transaction_hash,
                    "network": network,
                    "payer": result.payer,
                },
                status=status.HTTP_200_OK,
            )

        except X402FacilitatorValidationError as exc:
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
        except Exception as exc:
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
