import secrets
import uuid

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from pydantic import ValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from x402.schemas import VerifyRequest

from x402f.models import EnvarDelegationAuthorization, EnvarDelegationRegistration, X402Authorization
from x402f.views_official import (
    _configured,
    _invalid_verify,
    _parse_request,
    _payment_identity,
    _response,
    _verify_request,
)


class EnvarDelegationVerifyView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        supplied = request.headers.get("X-Envar-Delegation-Token", "")
        expected = settings.X402_ENVAR_DELEGATION_TOKEN
        if (
            not settings.X402_ENVAR_DELEGATION_ENABLED
            or not expected
            or not supplied
            or not secrets.compare_digest(supplied, expected)
        ):
            return Response({"error": "not_available"}, status=status.HTTP_403_FORBIDDEN)
        if not isinstance(request.data, dict) or set(request.data) != {"intent_id", "payment"}:
            return _invalid_verify("invalid_payment_request")
        try:
            intent_id = uuid.UUID(request.data["intent_id"])
            registration = EnvarDelegationRegistration.objects.get(pk=intent_id)
            if registration.expires_at <= timezone.now():
                return _invalid_verify("registration_expired")
            payment = _parse_request(request.data["payment"], VerifyRequest)
            requirements = payment.payment_requirements
            if (
                requirements.scheme != "exact"
                or str(requirements.network) != registration.network
                or requirements.asset.lower() != registration.asset.lower()
                or requirements.pay_to.lower() != registration.recipient.lower()
                or str(requirements.amount) != registration.amount_atomic
                or payment.payment_payload.accepted.model_dump(mode="json", by_alias=True)
                != requirements.model_dump(mode="json", by_alias=True)
            ):
                return _invalid_verify("registration_mismatch")
            authorization = payment.payment_payload.payload.get("authorization")
            if (
                not isinstance(authorization, dict)
                or str(authorization.get("to", "")).lower() != registration.recipient.lower()
                or str(authorization.get("value", "")) != registration.amount_atomic
            ):
                return _invalid_verify("authorization_mismatch")
            identity = _payment_identity(payment)
        except (KeyError, TypeError, ValueError, ValidationError, EnvarDelegationRegistration.DoesNotExist):
            return _invalid_verify("invalid_payment_request")
        serialized_requirements = requirements.model_dump(mode="json", by_alias=True)
        serialized_payload = payment.payment_payload.model_dump(mode="json", by_alias=True)
        existing = X402Authorization.objects.filter(nonce=identity.nonce).first()
        if existing:
            bound = EnvarDelegationAuthorization.objects.filter(
                registration=registration, authorization=existing
            ).exists()
            if (
                bound
                and existing.status == X402Authorization.Status.VERIFIED
                and existing.payment_requirements == serialized_requirements
                and existing.payment_payload == serialized_payload
                and existing.signature == identity.signature
            ):
                try:
                    result = _verify_request(payment, _configured(registration.network))
                except Exception:
                    return _invalid_verify("authorization_revalidation_failed")
                return _response(result)
            return _invalid_verify("authorization_conflict")
        if EnvarDelegationAuthorization.objects.filter(registration=registration).exists():
            return _invalid_verify("registration_already_bound")
        try:
            result = _verify_request(payment, _configured(registration.network))
        except Exception:
            return _invalid_verify("facilitator_verification_failed")
        if not result.is_valid:
            return _response(result)
        try:
            with transaction.atomic():
                authorization = X402Authorization.objects.create(
                    nonce=identity.nonce,
                    verification_id=str(registration.intent_id),
                    payer=result.payer or identity.payer,
                    pay_to=requirements.pay_to,
                    value=requirements.amount,
                    valid_after=identity.valid_after,
                    valid_before=identity.valid_before,
                    signature=identity.signature,
                    payment_requirements=serialized_requirements,
                    payment_payload=serialized_payload,
                    scheme="exact",
                )
                EnvarDelegationAuthorization.objects.create(registration=registration, authorization=authorization)
        except IntegrityError:
            return _invalid_verify("authorization_conflict")
        return _response(result)
