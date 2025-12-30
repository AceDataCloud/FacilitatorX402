"""
Multi-chain X402 facilitator views using ChainHandler pattern.
"""
from datetime import datetime, timezone as datetime_timezone
from typing import Dict, Any
import base64
import hashlib

from django.conf import settings
from django.db import transaction, IntegrityError
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


def _parse_payload(request_data: dict):
    """Parse payment payload and requirements from request data."""
    try:
        payload = request_data.get('paymentPayload', {})
        requirements = request_data.get('paymentRequirements', {})

        if not payload or not requirements:
            raise X402FacilitatorValidationError(
                'Missing paymentPayload or paymentRequirements'
            )

        return payload, requirements
    except Exception as exc:
        raise X402FacilitatorValidationError(
            f'Invalid request data: {exc}'
        ) from exc


def _get_chain_config(network: str) -> Dict[str, Any]:
    """
    Get chain-specific configuration from Django settings.

    For dynamic multi-chain support, configuration is keyed by network name.
    """
    # For Base chain
    network_lower = network.lower()
    if network_lower == 'base':
        return {
            'rpc_url': getattr(settings, 'X402_BASE_RPC_URL', ''),
            'signer_private_key': getattr(settings, 'X402_BASE_SIGNER_PRIVATE_KEY', ''),
            'signer_address': getattr(settings, 'X402_BASE_SIGNER_ADDRESS', ''),
            'fee_payer': getattr(settings, 'X402_BASE_FEE_PAYER', ''),
            'gas_limit': getattr(settings, 'X402_GAS_LIMIT', 250000),
            'tx_timeout_seconds': getattr(settings, 'X402_TX_TIMEOUT_SECONDS', 120),
            'max_fee_per_gas_wei': getattr(settings, 'X402_MAX_FEE_PER_GAS_WEI', 0),
            'max_priority_fee_per_gas_wei': getattr(settings, 'X402_MAX_PRIORITY_FEE_PER_GAS_WEI', 0),
        }
    # For Solana chain (mainnet/devnet)
    elif network_lower in ('solana', 'solana-devnet'):
        cluster = 'devnet' if network_lower == 'solana-devnet' else 'mainnet-beta'
        return {
            'rpc_url': getattr(
                settings,
                'X402_SOLANA_RPC_URL',
                'https://api.devnet.solana.com' if cluster == 'devnet' else 'https://api.mainnet-beta.solana.com',
            ),
            'signer_private_key': getattr(settings, 'X402_SOLANA_SIGNER_PRIVATE_KEY', ''),
            'signer_address': getattr(settings, 'X402_SOLANA_SIGNER_ADDRESS', ''),
            'fee_payer': getattr(settings, 'X402_SOLANA_FEE_PAYER', ''),
            'cluster': cluster,
        }
    else:
        raise X402FacilitatorError(f'Unsupported network: {network}')


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
            {'x402Version': 1, 'scheme': 'exact', 'network': network}
            for network in ChainHandlerFactory.get_supported_networks()
        ]
        return Response({'kinds': kinds}, status=status.HTTP_200_OK)


class X402VerifyView(APIView):
    """
    Verify payment authorization signature.

    Supports multiple chains dynamically based on the network field
    in payment requirements.
    """
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):
        try:
            payload, requirements = _parse_payload(request.data)
        except X402FacilitatorValidationError as exc:
            logger.info('x402 verification failed: {}', exc.message)
            return Response(
                {
                    'isValid': False,
                    'invalidReason': exc.message,
                    'payer': None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error('x402 verification misconfiguration: {}', exc)
            return Response(
                {
                    'isValid': False,
                    'invalidReason': 'Facilitator misconfiguration.',
                    'payer': None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Get network from requirements
        network = requirements.get('network', 'base')
        logger.debug(f'x402 verification for network: {network}')

        try:
            # Create chain handler for the network
            config = _get_chain_config(network)
            handler = ChainHandlerFactory.create(network, config)

            # Verify signature using chain handler
            result = handler.verify_signature(payload, requirements)

            if not result.is_valid:
                logger.info(
                    'x402 verification failed for network {}: {}',
                    network,
                    result.invalid_reason
                )
                return Response(
                    {
                        'isValid': False,
                        'invalidReason': result.invalid_reason,
                        'payer': result.payer,
                    },
                    status=status.HTTP_200_OK,
                )

            # Extract nonce and other data
            nonce = result.details.get('nonce') if result.details else payload.get(
                'payload', {}).get('nonce')
            # Always capture signature (top-level or nested) for storage/fallback
            signature = payload.get('signature') or payload.get(
                'payload', {}).get('signature', '')
            if not nonce:
                # Try to get from transaction data
                tx_data = payload.get('payload', {}).get('transaction', {})
                nonce = tx_data.get('nonce') if tx_data else None

            if not nonce:
                # Generate a unique identifier from signature
                nonce = f"{network}:{signature[:32]}"

            # Store authorization record
            try:
                with transaction.atomic():
                    record = X402Authorization(
                        nonce=str(nonce),
                        payer=result.payer,
                        pay_to=requirements.get('payTo', ''),
                        value=str(result.details.get('amount', 0)
                                  ) if result.details else '0',
                        valid_after=datetime.now(
                            datetime_timezone.utc),  # Simplified
                        valid_before=datetime.now(
                            datetime_timezone.utc),  # Simplified
                        signature=signature,
                        payment_requirements=requirements,
                        payment_payload=payload,
                    )
                    record.save(force_insert=True)
            except IntegrityError:
                logger.info(
                    'x402 authorization replay detected for nonce {}', nonce)
                return Response(
                    {
                        'isValid': False,
                        'invalidReason': 'Authorization nonce already processed.',
                        'payer': None,
                    },
                    status=status.HTTP_200_OK,
                )

            logger.debug('x402 authorization stored: nonce={} payer={} network={}',
                         nonce, result.payer, network)

            return Response(
                {
                    'isValid': True,
                    'invalidReason': None,
                    'payer': result.payer,
                },
                status=status.HTTP_200_OK,
            )

        except ValueError as exc:
            # Unsupported network
            logger.error('x402 unsupported network {}: {}', network, exc)
            return Response(
                {
                    'isValid': False,
                    'invalidReason': f'Unsupported network: {network}',
                    'payer': None,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error('x402 verification error: {}', exc)
            import traceback
            logger.error(traceback.format_exc())
            return Response(
                {
                    'isValid': False,
                    'invalidReason': f'Verification error: {str(exc)}',
                    'payer': None,
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
        try:
            payload, requirements = _parse_payload(request.data)
        except X402FacilitatorValidationError as exc:
            logger.info('x402 settlement validation failed: {}', exc.message)
            return Response(
                {
                    'success': False,
                    'errorReason': exc.message,
                    'transaction': None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error('x402 settlement misconfiguration: {}', exc)
            return Response(
                {
                    'success': False,
                    'errorReason': 'Facilitator misconfiguration.',
                    'transaction': None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Get network from requirements
        network = requirements.get('network', 'base')
        logger.debug(f'x402 settlement for network: {network}')

        # Extract nonce from payload, handling both EVM and Solana shapes
        raw_payload = payload.get('payload')
        signature = payload.get('signature') or (raw_payload.get(
            'signature') if isinstance(raw_payload, dict) else '')

        nonce = None
        auth = raw_payload.get('authorization') if isinstance(
            raw_payload, dict) else {}
        if isinstance(raw_payload, dict):
            nonce = raw_payload.get('nonce') or (auth or {}).get('nonce')
            tx_data = (
                raw_payload.get('serializedTransaction')
                or raw_payload.get('serialized_transaction')
                or raw_payload.get('transaction')
            )
            if nonce is None and isinstance(tx_data, dict):
                nonce = tx_data.get('nonce')
        else:
            # raw_payload might be a base64 solana transaction string
            tx_data = raw_payload

        # For solana, derive nonce from first signature if not provided
        if nonce is None and str(network).lower().startswith('solana') and tx_data:
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
            with transaction.atomic():
                try:
                    record = X402Authorization.objects.select_for_update().get(nonce=str(nonce))
                except X402Authorization.DoesNotExist:
                    logger.info(
                        'x402 settlement attempted without prior verification for nonce {}', nonce)
                    return Response(
                        {
                            'success': False,
                            'errorReason': 'Authorization nonce not verified.',
                            'transaction': None,
                        },
                        status=status.HTTP_200_OK,
                    )

                if record.status == X402Authorization.Status.SETTLED:
                    raise X402FacilitatorValidationError(
                        'Authorization nonce already settled.'
                    )

                # Create chain handler
                config = _get_chain_config(network)
                handler = ChainHandlerFactory.create(network, config)

                # Settle payment using chain handler
                result = handler.settle_payment(payload, requirements)

                if not result.success:
                    logger.exception(
                        'x402 settlement failed for network {}: {}',
                        network,
                        result.error_reason
                    )
                    return Response(
                        {
                            'success': False,
                            'errorReason': result.error_reason,
                            'transaction': result.transaction_hash,
                        },
                        status=status.HTTP_200_OK,
                    )

                # Mark as settled
                record.mark_settled(result.transaction_hash)
                record.save(update_fields=[
                    'status', 'transaction_hash', 'settled_at', 'updated_at'
                ])

                logger.info(
                    'x402 settlement succeeded for nonce {} tx {} network {}',
                    nonce,
                    result.transaction_hash,
                    network
                )

                return Response(
                    {
                        'success': True,
                        'errorReason': None,
                        'transaction': result.transaction_hash,
                        'network': network,
                        'payer': result.payer,
                    },
                    status=status.HTTP_200_OK,
                )

        except X402FacilitatorValidationError as exc:
            logger.info('x402 settlement rejected: {}', exc.message)
            return Response(
                {
                    'success': False,
                    'errorReason': exc.message,
                    'transaction': None,
                },
                status=status.HTTP_200_OK,
            )
        except ValueError as exc:
            # Unsupported network
            logger.error('x402 unsupported network {}: {}', network, exc)
            return Response(
                {
                    'success': False,
                    'errorReason': f'Unsupported network: {network}',
                    'transaction': None,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error('x402 settlement error: {}', exc)
            import traceback
            logger.error(traceback.format_exc())
            return Response(
                {
                    'success': False,
                    'errorReason': f'Settlement error: {str(exc)}',
                    'transaction': None,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
