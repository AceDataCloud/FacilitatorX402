import re
import secrets
import uuid
from datetime import datetime, timezone

from django.conf import settings
from django.db import IntegrityError, transaction
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from x402f.models import EnvarDelegationRegistration

ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
AMOUNT = re.compile(r"[1-9][0-9]{0,4}\Z")
FIELDS = {
    "intent_id",
    "parent_run_id",
    "attempt_id",
    "request_owner_account_id",
    "agent_id",
    "owner_account_id",
    "agent_version_id",
    "payee_revision",
    "recipient",
    "network",
    "asset",
    "amount_atomic",
    "terms_digest",
    "expires_at",
}
BASE_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _parse(value):  # noqa: ANN001, ANN202
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Registration fields are invalid")
    try:
        intent_id = uuid.UUID(value["intent_id"])
        parent_run_id = uuid.UUID(value["parent_run_id"])
        attempt_id = uuid.UUID(value["attempt_id"])
        agent_id = uuid.UUID(value["agent_id"])
        version_id = uuid.UUID(value["agent_version_id"])
        expiry = datetime.fromisoformat(value["expires_at"])
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise ValueError("Registration identity is invalid") from exc
    owner = value["owner_account_id"]
    requester = value["request_owner_account_id"]
    revision = value["payee_revision"]
    amount = value["amount_atomic"]
    recipient = value["recipient"]
    asset = value["asset"]
    digest = value["terms_digest"]
    if (
        not isinstance(requester, str)
        or not 1 <= len(requester) <= 64
        or not isinstance(owner, str)
        or not 1 <= len(owner) <= 64
        or type(revision) is not int
        or revision < 1
        or not isinstance(amount, str)
        or not AMOUNT.fullmatch(amount)
        or int(amount) > 10_000
        or not isinstance(recipient, str)
        or not ADDRESS.fullmatch(recipient)
        or not isinstance(asset, str)
        or asset.lower() != BASE_ASSET.lower()
        or value["network"] != "eip155:8453"
        or not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or expiry.tzinfo is None
        or expiry <= datetime.now(timezone.utc)
    ):
        raise ValueError("Registration terms are invalid")
    return {
        "intent_id": intent_id,
        "parent_run_id": parent_run_id,
        "attempt_id": attempt_id,
        "request_owner_account_id": requester,
        "agent_id": agent_id,
        "owner_account_id": owner,
        "agent_version_id": version_id,
        "payee_revision": revision,
        "recipient": recipient.lower(),
        "network": "eip155:8453",
        "asset": BASE_ASSET.lower(),
        "amount_atomic": amount,
        "terms_digest": digest,
        "expires_at": expiry,
    }


class EnvarDelegationRegisterView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        expected = settings.X402_ENVAR_DELEGATION_TOKEN
        supplied = request.headers.get("X-Envar-Delegation-Token", "")
        if (
            not settings.X402_ENVAR_DELEGATION_ENABLED
            or not expected
            or not supplied
            or not secrets.compare_digest(supplied, expected)
        ):
            return Response({"error": "not_available"}, status=status.HTTP_403_FORBIDDEN)
        try:
            terms = _parse(request.data)
        except ValueError:
            return Response({"error": "invalid_registration"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                row, created = EnvarDelegationRegistration.objects.get_or_create(
                    intent_id=terms["intent_id"],
                    defaults=terms,
                )
        except IntegrityError:
            return Response({"error": "registration_conflict"}, status=status.HTTP_409_CONFLICT)
        if any(getattr(row, field) != value for field, value in terms.items()):
            return Response({"error": "registration_conflict"}, status=status.HTTP_409_CONFLICT)
        response = Response({"intent_id": str(row.intent_id), "registered": True}, status=201 if created else 200)
        response["Cache-Control"] = "no-store"
        return response
