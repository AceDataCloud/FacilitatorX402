import secrets
import uuid

from django.conf import settings
from django.utils import timezone
from pydantic import ValidationError
from rest_framework import status
from rest_framework.views import APIView
from x402.schemas import SettleRequest

from x402f.models import EnvarDelegationAuthorization, EnvarDelegationRegistration, X402Authorization
from x402f.views_official import (
    _failed_settle,
    _parse_request,
    _payment_identity,
    _settle_verified_authorization,
)


class EnvarDelegationSettleView(APIView):
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
            return _failed_settle("invalid_payment_request", status_code=status.HTTP_403_FORBIDDEN)
        if not isinstance(request.data, dict) or set(request.data) != {"intent_id", "payment"}:
            return _failed_settle("invalid_payment_request")
        try:
            intent_id = uuid.UUID(request.data["intent_id"])
            registration = EnvarDelegationRegistration.objects.get(pk=intent_id)
            payment = _parse_request(request.data["payment"], SettleRequest)
            requirements = payment.payment_requirements
            authorization = payment.payment_payload.payload.get("authorization")
            if (
                requirements.scheme != "exact"
                or str(requirements.network) != registration.network
                or requirements.asset.lower() != registration.asset.lower()
                or requirements.pay_to.lower() != registration.recipient.lower()
                or str(requirements.amount) != registration.amount_atomic
                or payment.payment_payload.accepted.model_dump(mode="json", by_alias=True)
                != requirements.model_dump(mode="json", by_alias=True)
                or not isinstance(authorization, dict)
                or str(authorization.get("to", "")).lower() != registration.recipient.lower()
                or str(authorization.get("value", "")) != registration.amount_atomic
            ):
                return _failed_settle("payment_mismatch")
            identity = _payment_identity(payment)
            binding = EnvarDelegationAuthorization.objects.select_related("authorization").get(
                registration=registration, authorization__nonce=identity.nonce
            )
            record = binding.authorization
        except (KeyError, TypeError, ValueError, ValidationError, EnvarDelegationRegistration.DoesNotExist):
            return _failed_settle("invalid_payment_request")
        except EnvarDelegationAuthorization.DoesNotExist:
            return _failed_settle("authorization_not_verified")
        if record.status == X402Authorization.Status.VERIFIED and registration.expires_at <= timezone.now():
            return _failed_settle("registration_expired")
        if record.verification_id != str(registration.intent_id):
            return _failed_settle("authorization_conflict")
        return _settle_verified_authorization(payment, identity, record)
