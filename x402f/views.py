from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
from typing import Tuple

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from eth_account import Account
from eth_account.messages import encode_typed_data
from hexbytes import HexBytes
from loguru import logger
from pydantic import ValidationError as PydanticValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from web3 import HTTPProvider, Web3
from web3.exceptions import ContractLogicError

from x402.chains import get_chain_id
from x402.types import PaymentPayload, PaymentRequirements

from x402f.models import X402Authorization


USDC_TRANSFER_WITH_AUTHORIZATION_ABI = [
    {
        'inputs': [
            {'internalType': 'address', 'name': 'from', 'type': 'address'},
            {'internalType': 'address', 'name': 'to', 'type': 'address'},
            {'internalType': 'uint256', 'name': 'value', 'type': 'uint256'},
            {'internalType': 'uint256', 'name': 'validAfter', 'type': 'uint256'},
            {'internalType': 'uint256', 'name': 'validBefore', 'type': 'uint256'},
            {'internalType': 'bytes32', 'name': 'nonce', 'type': 'bytes32'},
            {'internalType': 'uint8', 'name': 'v', 'type': 'uint8'},
            {'internalType': 'bytes32', 'name': 'r', 'type': 'bytes32'},
            {'internalType': 'bytes32', 'name': 's', 'type': 'bytes32'},
        ],
        'name': 'transferWithAuthorization',
        'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
        'stateMutability': 'nonpayable',
        'type': 'function',
    }
]


class X402FacilitatorError(Exception):
    """Base error for facilitator failures."""


class X402FacilitatorValidationError(X402FacilitatorError):
    """Raised when incoming payload fails validation."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class ValidatedAuthorization:
    payload: PaymentPayload
    requirements: PaymentRequirements
    nonce: str
    payer: str
    pay_to: str
    value: int
    valid_after_ts: int
    valid_before_ts: int
    signature: str


def _normalize_address(address: str) -> str:
    try:
        return Web3.to_checksum_address(address)
    except ValueError as exc:
        raise X402FacilitatorValidationError(
            f'Invalid ethereum address: {address}'
        ) from exc


def _normalize_nonce(nonce: str) -> Tuple[str, HexBytes]:
    try:
        nonce_bytes = HexBytes(nonce)
    except (ValueError, TypeError) as exc:
        raise X402FacilitatorValidationError(
            'Authorization nonce must be hex encoded.') from exc
    if len(nonce_bytes) != 32:
        raise X402FacilitatorValidationError(
            'Authorization nonce must be 32 bytes.')
    return nonce_bytes.hex(), nonce_bytes


def _parse_payload(request_data: dict) -> Tuple[PaymentPayload, PaymentRequirements]:
    try:
        payload = PaymentPayload.model_validate(request_data['paymentPayload'])
        requirements = PaymentRequirements.model_validate(
            request_data['paymentRequirements'])
    except KeyError as exc:
        raise X402FacilitatorValidationError(
            f'Missing field: {exc.args[0]}') from exc
    except PydanticValidationError as exc:
        logger.debug('pydantic validation failed: {}', exc)
        raise X402FacilitatorValidationError(
            'Invalid payment payload or requirements.') from exc
    return payload, requirements


def _build_typed_data(requirements: PaymentRequirements, payload: PaymentPayload) -> dict:
    authorization = payload.payload.authorization
    extra = requirements.extra or {}
    domain_name = extra.get('name', '')
    domain_version = extra.get('version', '')
    if not domain_name or not domain_version:
        raise X402FacilitatorValidationError(
            'Payment requirements missing token domain metadata.')
    try:
        chain_id = int(get_chain_id(str(requirements.network)))
    except ValueError as exc:
        raise X402FacilitatorValidationError(str(exc)) from exc

    nonce_bytes = HexBytes(authorization.nonce)

    return {
        'types': {
            'EIP712Domain': [
                {'name': 'name', 'type': 'string'},
                {'name': 'version', 'type': 'string'},
                {'name': 'chainId', 'type': 'uint256'},
                {'name': 'verifyingContract', 'type': 'address'},
            ],
            'TransferWithAuthorization': [
                {'name': 'from', 'type': 'address'},
                {'name': 'to', 'type': 'address'},
                {'name': 'value', 'type': 'uint256'},
                {'name': 'validAfter', 'type': 'uint256'},
                {'name': 'validBefore', 'type': 'uint256'},
                {'name': 'nonce', 'type': 'bytes32'},
            ],
        },
        'primaryType': 'TransferWithAuthorization',
        'domain': {
            'name': domain_name,
            'version': domain_version,
            'chainId': chain_id,
            'verifyingContract': Web3.to_checksum_address(requirements.asset),
        },
        'message': {
            'from': _normalize_address(authorization.from_),
            'to': _normalize_address(authorization.to),
            'value': int(authorization.value),
            'validAfter': int(authorization.valid_after),
            'validBefore': int(authorization.valid_before),
            'nonce': nonce_bytes,
        },
    }


def _recover_payer_address(typed_data: dict, signature: str) -> str:
    try:
        signable = encode_typed_data(full_message=typed_data)
    except Exception as exc:  # pragma: no cover - encode_typed_data raises many exception types
        raise X402FacilitatorValidationError(
            'Failed to encode authorization for signature recovery.') from exc

    try:
        recovered = Account.recover_message(signable, signature=signature)
    except Exception as exc:
        raise X402FacilitatorValidationError(
            'Unable to recover signer from signature.') from exc

    return _normalize_address(recovered)


def _validate_payload(payload: PaymentPayload, requirements: PaymentRequirements) -> ValidatedAuthorization:
    expected_pay_to = (settings.X402_CONFIG or {}).get('pay_to')
    expected_network = (settings.X402_CONFIG or {}).get('network')
    expected_asset = getattr(settings, 'X402_USDC_CONTRACT', '').lower()

    if not expected_pay_to or not expected_network or not expected_asset:
        raise X402FacilitatorError(
            'X402 facilitator configuration is incomplete.')

    network_value = str(requirements.network)
    if network_value.lower() != str(expected_network).lower():
        raise X402FacilitatorValidationError('Payment network mismatch.')

    if requirements.pay_to.lower() != expected_pay_to.lower():
        raise X402FacilitatorValidationError('Payment destination mismatch.')

    if requirements.asset.lower() != expected_asset:
        raise X402FacilitatorValidationError('Unsupported payment asset.')

    authorization = payload.payload.authorization

    if authorization.to.lower() != expected_pay_to.lower():
        raise X402FacilitatorValidationError(
            'Authorization destination mismatch.')

    max_amount = int(requirements.max_amount_required)
    value = int(authorization.value)
    if value <= 0:
        raise X402FacilitatorValidationError(
            'Authorization value must be positive.')
    if value > max_amount:
        raise X402FacilitatorValidationError(
            'Authorization value exceeds the required cap.')

    now_ts = int(timezone.now().timestamp())
    valid_after = int(authorization.valid_after)
    valid_before = int(authorization.valid_before)

    if valid_before <= now_ts:
        raise X402FacilitatorValidationError(
            'Authorization window has expired.')
    if valid_after > now_ts:
        raise X402FacilitatorValidationError('Authorization not yet valid.')

    signature = payload.payload.signature
    if not signature:
        raise X402FacilitatorValidationError(
            'Authorization signature missing.')

    nonce_hex, _ = _normalize_nonce(authorization.nonce)

    typed_data = _build_typed_data(requirements, payload)
    payer = _recover_payer_address(typed_data, signature)

    if payer.lower() != authorization.from_.lower():
        raise X402FacilitatorValidationError(
            'Signature does not match authorization originator.')

    return ValidatedAuthorization(
        payload=payload,
        requirements=requirements,
        nonce=nonce_hex,
        payer=payer,
        pay_to=_normalize_address(authorization.to),
        value=value,
        valid_after_ts=valid_after,
        valid_before_ts=valid_before,
        signature=signature,
    )


def _signature_to_components(signature: str) -> Tuple[int, bytes, bytes]:
    try:
        signature_bytes = HexBytes(signature)
    except (ValueError, TypeError) as exc:
        raise X402FacilitatorValidationError(
            'Invalid authorization signature.') from exc
    if len(signature_bytes) != 65:
        raise X402FacilitatorValidationError(
            'Authorization signature must be 65 bytes.')

    r = signature_bytes[:32]
    s = signature_bytes[32:64]
    v = signature_bytes[64]
    if v < 27:
        v += 27
    return int(v), bytes(r), bytes(s)


def _submit_transfer_with_authorization(data: ValidatedAuthorization) -> str:
    rpc_url = getattr(settings, 'X402_RPC_URL', '')
    private_key = getattr(settings, 'X402_SIGNER_PRIVATE_KEY', '')
    configured_address = getattr(settings, 'X402_SIGNER_ADDRESS', '')
    timeout = getattr(settings, 'X402_TX_TIMEOUT_SECONDS', 120)
    gas_limit = getattr(settings, 'X402_GAS_LIMIT', 250000)
    max_fee = getattr(settings, 'X402_MAX_FEE_PER_GAS_WEI', 0)
    max_priority_fee = getattr(
        settings, 'X402_MAX_PRIORITY_FEE_PER_GAS_WEI', 0)

    if not rpc_url:
        raise X402FacilitatorError('X402_RPC_URL is not configured.')
    if not private_key:
        raise X402FacilitatorError(
            'X402_SIGNER_PRIVATE_KEY is not configured.')

    web3 = Web3(HTTPProvider(rpc_url))
    if not web3.is_connected():
        raise X402FacilitatorError(
            'Unable to connect to configured RPC endpoint.')

    account = web3.eth.account.from_key(private_key)
    signer_address = _normalize_address(configured_address or account.address)

    contract = web3.eth.contract(
        address=_normalize_address(settings.X402_USDC_CONTRACT),
        abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
    )

    authorization = data.payload.payload.authorization
    nonce_bytes = HexBytes(authorization.nonce)
    v, r, s = _signature_to_components(data.signature)

    transfer_fn = contract.functions.transferWithAuthorization(
        _normalize_address(authorization.from_),
        _normalize_address(authorization.to),
        int(authorization.value),
        int(authorization.valid_after),
        int(authorization.valid_before),
        nonce_bytes,
        v,
        r,
        s,
    )

    try:
        estimated_gas = transfer_fn.estimate_gas({'from': signer_address})
    except Exception as exc:  # pragma: no cover - estimation often fails in tests
        logger.debug(
            'Gas estimation failed, falling back to configured gas limit: {}', exc)
        estimated_gas = gas_limit

    tx_params = {
        'chainId': int(get_chain_id(str(data.requirements.network))),
        'from': signer_address,
        'nonce': web3.eth.get_transaction_count(signer_address),
        'gas': max(estimated_gas, gas_limit),
    }

    if max_fee and max_priority_fee:
        tx_params['maxFeePerGas'] = int(max_fee)
        tx_params['maxPriorityFeePerGas'] = int(max_priority_fee)
    else:
        tx_params['gasPrice'] = web3.eth.gas_price

    transaction = transfer_fn.build_transaction(tx_params)
    signed = web3.eth.account.sign_transaction(
        transaction, private_key=private_key)

    raw_tx = getattr(signed, 'rawTransaction', None)
    if raw_tx is None:
        raw_tx = getattr(signed, 'raw_transaction', None)
    if raw_tx is None:
        raise X402FacilitatorError(
            'Signer returned unexpected transaction encoding.')

    tx_hash = web3.eth.send_raw_transaction(raw_tx)
    logger.debug(
        'Submitted transferWithAuthorization transaction: {}', tx_hash.hex())

    try:
        receipt = web3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=timeout)
    except Exception as exc:
        raise X402FacilitatorError(
            'Timed out waiting for settlement transaction.') from exc

    if receipt.status != 1:
        raise X402FacilitatorError('Settlement transaction reverted on-chain.')

    return tx_hash.hex()


class X402VerifyView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):
        try:
            payload, requirements = _parse_payload(request.data)
            validated = _validate_payload(payload, requirements)
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

        try:
            valid_after_dt = datetime.fromtimestamp(
                validated.valid_after_ts, tz=datetime_timezone.utc)
            valid_before_dt = datetime.fromtimestamp(
                validated.valid_before_ts, tz=datetime_timezone.utc)

            with transaction.atomic():
                record = X402Authorization(
                    nonce=validated.nonce,
                    payer=validated.payer,
                    pay_to=validated.pay_to,
                    value=str(validated.value),
                    valid_after=valid_after_dt,
                    valid_before=valid_before_dt,
                    signature=validated.signature,
                    payment_requirements=validated.requirements.model_dump(
                        by_alias=True, exclude_none=True),
                    payment_payload=validated.payload.model_dump(
                        by_alias=True, exclude_none=True),
                )
                record.save(force_insert=True)
        except IntegrityError:
            logger.info(
                'x402 authorization replay detected for nonce {}', validated.nonce)
            return Response(
                {
                    'isValid': False,
                    'invalidReason': 'Authorization nonce already processed.',
                    'payer': None,
                },
                status=status.HTTP_200_OK,
            )

        logger.debug('x402 authorization stored: nonce={} payer={}',
                     validated.nonce, validated.payer)
        return Response(
            {
                'isValid': True,
                'invalidReason': None,
                'payer': validated.payer,
            },
            status=status.HTTP_200_OK,
        )


class X402SettleView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs) -> Response:
        try:
            payload, requirements = _parse_payload(request.data)
            validated = _validate_payload(payload, requirements)
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

        try:
            with transaction.atomic():
                record = X402Authorization.objects.select_for_update().get(nonce=validated.nonce)
                if record.status == X402Authorization.Status.SETTLED:
                    raise X402FacilitatorValidationError(
                        'Authorization nonce already settled.')

                if record.signature.lower() != validated.signature.lower():
                    raise X402FacilitatorValidationError(
                        'Authorization signature mismatch.')

                if record.payer.lower() != validated.payer.lower():
                    raise X402FacilitatorValidationError(
                        'Authorization signer mismatch.')

                if int(record.value) != validated.value:
                    raise X402FacilitatorValidationError(
                        'Authorization value mismatch.')

                tx_hash = _submit_transfer_with_authorization(validated)
                record.mark_settled(tx_hash)
                record.save(update_fields=[
                            'status', 'transaction_hash', 'settled_at', 'updated_at'])
        except X402Authorization.DoesNotExist:
            logger.info(
                'x402 settlement attempted without prior verification for nonce {}', validated.nonce)
            return Response(
                {
                    'success': False,
                    'errorReason': 'Authorization nonce not verified.',
                    'transaction': None,
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
        except ContractLogicError as exc:
            logger.error('x402 settlement reverted on-chain: {}', exc)
            return Response(
                {
                    'success': False,
                    'errorReason': 'Settlement transaction reverted on-chain.',
                    'transaction': None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error('x402 settlement failed: {}', exc)
            return Response(
                {
                    'success': False,
                    'errorReason': str(exc),
                    'transaction': None,
                },
                status=status.HTTP_200_OK,
            )

        logger.info('x402 settlement succeeded for nonce {} tx {}',
                    validated.nonce, tx_hash)
        return Response(
            {
                'success': True,
                'errorReason': None,
                'transaction': tx_hash,
                'network': str(validated.requirements.network),
                'payer': validated.payer,
            },
            status=status.HTTP_200_OK,
        )
