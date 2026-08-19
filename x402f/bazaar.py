from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from copy import deepcopy
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from x402.extensions.bazaar import validate_discovery_extension, validate_discovery_extension_spec

from x402f.models import BazaarCatalogSnapshot
from x402f.official import configured_supported_response


class BazaarCatalogError(ValueError):
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _read_json(request: urllib.request.Request, *, max_bytes: int, timeout: float) -> tuple[dict[str, Any], Any]:
    try:
        opener = urllib.request.build_opener(NoRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
            headers = response.headers
    except (OSError, urllib.error.URLError) as exc:
        raise BazaarCatalogError("Bazaar endpoint is unavailable") from exc
    if len(raw) > max_bytes:
        raise BazaarCatalogError("Bazaar response is too large")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise BazaarCatalogError("Bazaar endpoint returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise BazaarCatalogError("Bazaar endpoint returned an invalid object")
    return payload, headers


def fetch_catalog() -> dict[str, Any]:
    parsed = urlsplit(settings.X402_BAZAAR_CATALOG_URL)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "platform.acedata.cloud"
        or parsed.port not in {None, 443}
        or parsed.username
        or parsed.password
    ):
        raise BazaarCatalogError("Bazaar catalog URL must use the platform control-plane origin")
    if parsed.path != "/api/v1/x402/bazaar-catalog/" or parsed.query or parsed.fragment:
        raise BazaarCatalogError("Bazaar catalog URL is invalid")
    if not settings.X402_BAZAAR_CATALOG_ACCESS_TOKEN:
        raise BazaarCatalogError("Bazaar catalog access token is missing")
    request = urllib.request.Request(
        f"{settings.X402_BAZAAR_CATALOG_URL}?limit=200",
        headers={"X-Internal-Token": settings.X402_BAZAAR_CATALOG_ACCESS_TOKEN},
    )
    payload, _ = _read_json(
        request,
        max_bytes=settings.X402_BAZAAR_MAX_CATALOG_BYTES,
        timeout=settings.X402_BAZAAR_PROBE_TIMEOUT_SECONDS,
    )
    verify_catalog(payload)
    return payload


def verify_catalog(payload: dict[str, Any]) -> None:
    secret = settings.X402_BAZAAR_CATALOG_SIGNING_SECRET
    if not secret:
        raise BazaarCatalogError("Bazaar catalog signing secret is missing")
    items = payload.get("items")
    pagination = payload.get("pagination") or {}
    if not isinstance(items, list) or pagination.get("nextCursor") is not None or pagination.get("total") != len(items):
        raise BazaarCatalogError("Bazaar catalog must be one complete page")

    unsigned_items = deepcopy(items)
    for item in unsigned_items:
        if isinstance(item, dict) and isinstance(item.get("source"), dict):
            for key in ("snapshot", "manifestSha256", "signature"):
                item["source"].pop(key, None)
    core = {"version": payload.get("version"), "resources": unsigned_items}
    manifest = sha256(core)
    snapshot = hashlib.sha256(f"{payload.get('version')}:{manifest}".encode()).hexdigest()
    expected = hmac.new(secret.encode(), canonical_json({**core, "snapshot": snapshot}), hashlib.sha256).digest()
    try:
        signature = base64.b64decode(str(payload.get("signature") or ""), validate=True)
    except Exception as exc:
        raise BazaarCatalogError("Bazaar catalog signature is invalid") from exc
    if (
        not hmac.compare_digest(manifest, str(payload.get("manifestSha256") or ""))
        or not hmac.compare_digest(snapshot, str(payload.get("snapshot") or ""))
        or not hmac.compare_digest(expected, signature)
    ):
        raise BazaarCatalogError("Bazaar catalog snapshot proof is invalid")

    page = {"snapshot": snapshot, "offset": 0, "items": items}
    page_manifest = sha256(page)
    expected_page = hmac.new(secret.encode(), canonical_json(page), hashlib.sha256).digest()
    try:
        page_signature = base64.b64decode(str(payload.get("pageSignature") or ""), validate=True)
    except Exception as exc:
        raise BazaarCatalogError("Bazaar catalog page signature is invalid") from exc
    if not hmac.compare_digest(page_manifest, str(payload.get("pageManifestSha256") or "")) or not hmac.compare_digest(
        expected_page, page_signature
    ):
        raise BazaarCatalogError("Bazaar catalog page proof is invalid")


def _expected_resource(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c in path for c in "?#\\"):
        raise BazaarCatalogError("Bazaar resource path is invalid")
    origin = urlsplit(settings.X402_BAZAAR_RESOURCE_ORIGIN)
    if origin.scheme != "https" or origin.hostname != "x402.acedata.cloud" or origin.path not in {"", "/"}:
        raise BazaarCatalogError("Bazaar resource origin is invalid")
    return f"{settings.X402_BAZAAR_RESOURCE_ORIGIN}{path}"


def _same_identifier(network: str, actual: Any, expected: str) -> bool:
    if not isinstance(actual, str) or not actual or not expected:
        return False
    if network.startswith("eip155:"):
        return actual.lower() == expected.lower()
    return actual == expected


def _requirement_support_error(requirement: dict[str, Any]) -> str | None:
    network = str(requirement.get("network") or "")
    scheme = str(requirement.get("scheme") or "")
    expected = {
        settings.X402_BASE_NETWORK: (settings.X402_BASE_ASSET, settings.X402_BASE_PAY_TO),
        "eip155:1187947933": (settings.X402_SKALE_ASSET, settings.X402_SKALE_PAY_TO),
        "eip155:4663": (settings.X402_ROBINHOOD_ASSET, settings.X402_ROBINHOOD_PAY_TO),
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (settings.X402_SOLANA_ASSET, settings.X402_SOLANA_PAY_TO),
    }.get(network)
    supported = configured_supported_response()
    supported_kinds = {(str(kind.scheme), str(kind.network)) for kind in supported.kinds}
    if expected is None or (scheme, network) not in supported_kinds:
        return "unsupported_kind"
    if not _same_identifier(network, requirement.get("asset"), expected[0]):
        return "asset_mismatch"
    if not _same_identifier(network, requirement.get("payTo"), expected[1]):
        return "pay_to_mismatch"
    return None


def _supported_requirement(requirement: dict[str, Any]) -> bool:
    return _requirement_support_error(requirement) is None


def _challenge(item: dict[str, Any]) -> dict[str, Any]:
    method = item.get("method")
    path = item.get("path")
    extensions = item.get("extensions")
    if (
        method not in {"POST", "PUT", "PATCH"}
        or not isinstance(extensions, dict)
        or not isinstance(extensions.get("bazaar"), dict)
    ):
        raise BazaarCatalogError("Bazaar catalog item is invalid")
    extension = extensions["bazaar"]
    validation = validate_discovery_extension(extension)
    spec_validation = validate_discovery_extension_spec(extension)
    if not validation.valid or not spec_validation.valid:
        raise BazaarCatalogError("Bazaar extension is invalid")
    info = extension.get("info") or {}
    input_info = info.get("input") or {}
    if input_info.get("method") != method or input_info.get("bodyType") != "json":
        raise BazaarCatalogError("Bazaar extension method is invalid")
    body = input_info.get("body")
    if not isinstance(body, dict):
        raise BazaarCatalogError("Bazaar request example is invalid")
    resource = _expected_resource(path)
    request = urllib.request.Request(
        resource,
        data=canonical_json(body),
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        payload, headers = _read_json(
            request,
            max_bytes=settings.X402_BAZAAR_MAX_CHALLENGE_BYTES,
            timeout=settings.X402_BAZAAR_PROBE_TIMEOUT_SECONDS,
        )
    except BazaarCatalogError as exc:
        if not isinstance(exc.__cause__, urllib.error.HTTPError) or exc.__cause__.code != 402:
            cause = exc.__cause__
            status = f"HTTP {cause.code}" if isinstance(cause, urllib.error.HTTPError) else type(cause).__name__
            raise BazaarCatalogError(f"Bazaar challenge failed for {path} ({status})") from exc
        error = exc.__cause__
        raw = error.read(settings.X402_BAZAAR_MAX_CHALLENGE_BYTES + 1)
        if len(raw) > settings.X402_BAZAAR_MAX_CHALLENGE_BYTES:
            raise BazaarCatalogError("Bazaar challenge is too large") from exc
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as decode_exc:
            raise BazaarCatalogError("Bazaar challenge returned invalid JSON") from decode_exc
        headers = error.headers

    if payload.get("x402Version") != 2 or (payload.get("resource") or {}).get("url") != resource:
        raise BazaarCatalogError("Bazaar challenge resource is invalid")
    if payload.get("extensions") != extensions:
        raise BazaarCatalogError("Bazaar challenge extension does not match the signed catalog")
    accepts = payload.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        raise BazaarCatalogError("Bazaar challenge has no payment requirements")
    for requirement in accepts:
        if not isinstance(requirement, dict) or requirement.get("resource") != resource:
            raise BazaarCatalogError("Bazaar payment requirement resource is invalid")
        amount = str(requirement.get("amount") or "")
        if not amount.isdigit() or int(amount) <= 0:
            raise BazaarCatalogError("Bazaar payment requirement amount is invalid")
    encoded = headers.get("PAYMENT-REQUIRED") if headers else None
    try:
        header_payload = json.loads(base64.b64decode(encoded, validate=True))
    except Exception as exc:
        raise BazaarCatalogError("Bazaar PAYMENT-REQUIRED header is invalid") from exc
    if header_payload != payload:
        raise BazaarCatalogError("Bazaar challenge body and header do not match")
    supported_accepts = [requirement for requirement in accepts if _supported_requirement(requirement)]
    if not supported_accepts:
        reasons = sorted(
            {f"{requirement.get('network')}:{_requirement_support_error(requirement)}" for requirement in accepts}
        )
        raise BazaarCatalogError(f"Bazaar challenge has no supported payment requirements ({', '.join(reasons)})")
    projected = deepcopy(payload)
    projected["accepts"] = supported_accepts
    return projected


def project_catalog(source: dict[str, Any]) -> dict[str, Any]:
    now = timezone.now().isoformat()
    projected = []
    seen = set()
    for item in source["items"]:
        if not isinstance(item, dict) or item.get("stage") != "Production":
            raise BazaarCatalogError("Bazaar catalog includes a non-production resource")
        challenge = _challenge(item)
        resource = (challenge.get("resource") or {}).get("url")
        method = item.get("method")
        key = (method, resource)
        if key in seen:
            raise BazaarCatalogError("Bazaar catalog contains duplicate resources")
        seen.add(key)
        projected.append(
            {
                "resource": resource,
                "type": "http",
                "x402Version": 2,
                "accepts": challenge["accepts"],
                "lastUpdated": now,
                "description": (challenge.get("resource") or {}).get("description"),
                "mimeType": (challenge.get("resource") or {}).get("mimeType"),
                "extensions": challenge["extensions"],
            }
        )
    projected.sort(key=lambda value: value["resource"])
    return {
        "x402Version": 2,
        "items": projected,
        "pagination": {"limit": len(projected), "offset": 0, "total": len(projected)},
    }


def refresh_catalog() -> BazaarCatalogSnapshot:
    if not settings.X402_BAZAAR_ENABLED:
        raise BazaarCatalogError("Bazaar discovery is disabled")
    source = fetch_catalog()
    projected = project_catalog(source)
    now = timezone.now()
    expires_at = now + timedelta(seconds=settings.X402_BAZAAR_MAX_STALE_SECONDS)
    with transaction.atomic():
        BazaarCatalogSnapshot.objects.select_for_update().filter(status=BazaarCatalogSnapshot.Status.ACTIVE).update(
            status=BazaarCatalogSnapshot.Status.SUPERSEDED
        )
        snapshot, _ = BazaarCatalogSnapshot.objects.update_or_create(
            snapshot=source["snapshot"],
            defaults={
                "version": str(source["version"]),
                "manifest_sha256": source["manifestSha256"],
                "source_signature": source["signature"],
                "source_payload": source,
                "projected_payload": projected,
                "resource_count": len(projected["items"]),
                "status": BazaarCatalogSnapshot.Status.ACTIVE,
                "fetched_at": now,
                "probed_at": now,
                "activated_at": now,
                "expires_at": expires_at,
                "error_summary": "",
            },
        )
    return snapshot


def active_catalog() -> dict[str, Any] | None:
    snapshot = BazaarCatalogSnapshot.objects.filter(
        status=BazaarCatalogSnapshot.Status.ACTIVE,
        expires_at__gt=timezone.now(),
    ).first()
    return deepcopy(snapshot.projected_payload) if snapshot else None


def validate_payment_discovery(payment_payload: Any, payment_requirements: Any) -> None:
    extensions = getattr(payment_payload, "extensions", None)
    if not extensions or "bazaar" not in extensions:
        return
    resource = getattr(payment_payload, "resource", None)
    resource_url = str(getattr(resource, "url", "") or "")
    method = str(((extensions.get("bazaar") or {}).get("info") or {}).get("input", {}).get("method") or "")
    catalog = active_catalog()
    if catalog is None:
        raise BazaarCatalogError("Bazaar catalog is unavailable")
    match = next(
        (
            item
            for item in catalog.get("items", [])
            if item.get("resource") == resource_url
            and item.get("extensions", {}).get("bazaar", {}).get("info", {}).get("input", {}).get("method") == method
        ),
        None,
    )
    if match is None or match.get("extensions") != extensions:
        raise BazaarCatalogError("Bazaar payment extension does not match the active catalog")
    requirement = payment_requirements.model_dump(mode="json", by_alias=True)
    standard_fields = {"scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"}
    accepted = [{key: value.get(key) for key in standard_fields} for value in match.get("accepts", [])]
    if {key: requirement.get(key) for key in standard_fields} not in accepted:
        raise BazaarCatalogError("Bazaar payment requirement does not match the active catalog")
