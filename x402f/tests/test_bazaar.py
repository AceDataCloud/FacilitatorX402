import base64
import hashlib
import hmac
import json
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.test import TestCase, override_settings
from django.utils import timezone

from x402f import bazaar
from x402f.models import BazaarCatalogSnapshot

SECRET = "catalog-secret"
RESOURCE = "https://x402.acedata.cloud/serp/google"
EXTENSION = {
    "bazaar": {
        "info": {
            "input": {
                "type": "http",
                "method": "POST",
                "bodyType": "json",
                "body": {"query": "x402", "number": 1},
            },
            "output": {"type": "json", "example": {"organic": []}},
        },
        "schema": {
            "type": "object",
            "properties": {
                "input": {
                    "type": "object",
                    "properties": {
                        "type": {"const": "http"},
                        "method": {"const": "POST"},
                        "bodyType": {"const": "json"},
                        "body": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}, "number": {"type": "integer"}},
                            "required": ["query"],
                        },
                    },
                    "required": ["type", "method", "bodyType", "body"],
                }
            },
            "required": ["input"],
        },
    }
}
REQUIREMENT = {
    "scheme": "exact",
    "network": "eip155:8453",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "amount": "951",
    "payTo": "0x1111111111111111111111111111111111111111",
    "maxTimeoutSeconds": 3600,
    "resource": RESOURCE,
    "extra": {},
}


def signed_catalog() -> dict:
    item = {
        "resourceId": "api-id:POST:/serp/google",
        "apiId": "api-id",
        "serviceId": "service-id",
        "method": "POST",
        "path": "/serp/google",
        "stage": "Production",
        "description": "Search the web",
        "extensions": deepcopy(EXTENSION),
        "source": {"openapiSha256": "openapi", "resourceConfigSha256": "resource"},
    }
    core = {"version": "bazaar-v1", "resources": [item]}
    manifest = bazaar.sha256(core)
    snapshot = hashlib.sha256(f"bazaar-v1:{manifest}".encode()).hexdigest()
    signature = base64.b64encode(
        hmac.new(SECRET.encode(), bazaar.canonical_json({**core, "snapshot": snapshot}), hashlib.sha256).digest()
    ).decode()
    item["source"].update({"snapshot": snapshot, "manifestSha256": manifest, "signature": signature})
    page = {"snapshot": snapshot, "offset": 0, "items": [item]}
    return {
        "version": "bazaar-v1",
        "snapshot": snapshot,
        "manifestSha256": manifest,
        "signature": signature,
        "pageManifestSha256": bazaar.sha256(page),
        "pageSignature": base64.b64encode(
            hmac.new(SECRET.encode(), bazaar.canonical_json(page), hashlib.sha256).digest()
        ).decode(),
        "items": [item],
        "pagination": {"limit": 200, "nextCursor": None, "total": 1},
    }


def challenge() -> dict:
    return {
        "x402Version": 2,
        "resource": {"url": RESOURCE, "description": "Search the web", "mimeType": "application/json"},
        "accepts": [deepcopy(REQUIREMENT)],
        "extensions": deepcopy(EXTENSION),
        "error": "PAYMENT-SIGNATURE header is required",
    }


@override_settings(X402_BAZAAR_CATALOG_SIGNING_SECRET=SECRET)
def test_catalog_signature_and_page_proof_fail_closed() -> None:
    payload = signed_catalog()
    bazaar.verify_catalog(payload)

    payload["items"][0]["path"] = "/attacker"
    with pytest.raises(bazaar.BazaarCatalogError, match="proof"):
        bazaar.verify_catalog(payload)


@pytest.mark.parametrize(
    "url",
    [
        "http://platform-backend:8000/internal/v1/x402/bazaar-resources",
        "https://attacker.example/api/v1/x402/bazaar-catalog/",
        "https://platform.acedata.cloud/internal/v1/x402/bazaar-resources",
        "https://user@platform.acedata.cloud/api/v1/x402/bazaar-catalog/",
        "https://platform.acedata.cloud/api/v1/x402/bazaar-catalog/?next=evil",
    ],
)
@override_settings(
    X402_BAZAAR_CATALOG_ACCESS_TOKEN="access",
    X402_BAZAAR_CATALOG_SIGNING_SECRET=SECRET,
)
def test_catalog_source_rejects_noncanonical_cross_zone_urls(url) -> None:
    with override_settings(X402_BAZAAR_CATALOG_URL=url):
        with pytest.raises(bazaar.BazaarCatalogError, match="catalog URL"):
            bazaar.fetch_catalog()


@override_settings(
    X402_BAZAAR_CATALOG_URL="https://platform.acedata.cloud/api/v1/x402/bazaar-catalog/",
    X402_BAZAAR_CATALOG_ACCESS_TOKEN="access",
    X402_BAZAAR_CATALOG_SIGNING_SECRET=SECRET,
)
@patch("x402f.bazaar.verify_catalog")
@patch("x402f.bazaar._read_json")
def test_catalog_source_accepts_authenticated_platform_origin(read_json, verify_catalog) -> None:
    payload = signed_catalog()
    read_json.return_value = (payload, {})

    assert bazaar.fetch_catalog() == payload
    request = read_json.call_args.args[0]
    assert request.full_url == "https://platform.acedata.cloud/api/v1/x402/bazaar-catalog/?limit=200"
    assert request.headers["X-internal-token"] == "access"
    verify_catalog.assert_called_once_with(payload)


@override_settings(
    X402_BAZAAR_RESOURCE_ORIGIN="https://x402.acedata.cloud",
    X402_BASE_EXACT_ENABLED=True,
    X402_BASE_UPTO_ENABLED=False,
    X402_BASE_ASSET="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    X402_BASE_PAY_TO="0X1111111111111111111111111111111111111111",
    X402_BASE_SIGNER_ADDRESS="0x2222222222222222222222222222222222222222",
    X402_SOLANA_MAINNET_ENABLED=False,
    X402_SKALE_EXACT_ENABLED=False,
)
@patch("x402f.bazaar._read_json")
def test_challenge_probe_requires_canonical_equivalent_header(read_json) -> None:
    payload = challenge()
    header = base64.b64encode(json.dumps(payload).encode()).decode()
    read_json.return_value = (payload, {"PAYMENT-REQUIRED": header})

    assert bazaar._challenge(signed_catalog()["items"][0]) == payload

    wrong_asset = deepcopy(payload)
    wrong_asset["accepts"][0]["asset"] = "0x0000000000000000000000000000000000000000"
    read_json.return_value = (
        wrong_asset,
        {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(wrong_asset).encode()).decode()},
    )
    with pytest.raises(
        bazaar.BazaarCatalogError,
        match="eip155:8453:asset_mismatch",
    ) as exc_info:
        bazaar._challenge(signed_catalog()["items"][0])
    assert wrong_asset["accepts"][0]["asset"] not in str(exc_info.value)

    mixed = deepcopy(payload)
    unsupported = deepcopy(REQUIREMENT)
    unsupported["network"] = "eip155:999999"
    unsupported["asset"] = "0x0000000000000000000000000000000000000000"
    mixed["accepts"].insert(0, unsupported)
    read_json.return_value = (mixed, {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(mixed).encode()).decode()})

    projected = bazaar._challenge(signed_catalog()["items"][0])

    assert projected["accepts"] == [REQUIREMENT]

    invalid_unsupported = deepcopy(mixed)
    invalid_unsupported["accepts"][0]["amount"] = "0"
    read_json.return_value = (
        invalid_unsupported,
        {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(invalid_unsupported).encode()).decode()},
    )
    with pytest.raises(bazaar.BazaarCatalogError, match="amount"):
        bazaar._challenge(signed_catalog()["items"][0])

    tampered = deepcopy(payload)
    tampered["accepts"][0]["amount"] = "952"
    read_json.return_value = (payload, {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(tampered).encode()).decode()})
    with pytest.raises(bazaar.BazaarCatalogError, match="do not match"):
        bazaar._challenge(signed_catalog()["items"][0])


@override_settings(
    X402_BAZAAR_ENABLED=True,
    X402_BAZAAR_CATALOG_SIGNING_SECRET=SECRET,
    X402_BAZAAR_MAX_STALE_SECONDS=900,
)
class BazaarSnapshotTests(TestCase):
    @patch("x402f.bazaar.project_catalog")
    @patch("x402f.bazaar.fetch_catalog")
    def test_refresh_atomically_supersedes_previous_snapshot(self, fetch, project) -> None:
        old = BazaarCatalogSnapshot.objects.create(
            snapshot="old",
            version="v1",
            manifest_sha256="old",
            source_signature="old",
            source_payload={},
            projected_payload={"x402Version": 2, "items": []},
            resource_count=0,
            status=BazaarCatalogSnapshot.Status.ACTIVE,
            fetched_at=timezone.now(),
            activated_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        fetch.return_value = signed_catalog()
        project.return_value = {
            "x402Version": 2,
            "items": [{"resource": RESOURCE, "accepts": [REQUIREMENT], "extensions": EXTENSION}],
            "pagination": {"limit": 1, "offset": 0, "total": 1},
        }

        current = bazaar.refresh_catalog()

        old.refresh_from_db()
        assert old.status == BazaarCatalogSnapshot.Status.SUPERSEDED
        assert current.status == BazaarCatalogSnapshot.Status.ACTIVE
        assert current.resource_count == 1
        assert bazaar.active_catalog()["items"][0]["resource"] == RESOURCE

    def test_public_discovery_filters_active_snapshot(self) -> None:
        BazaarCatalogSnapshot.objects.create(
            snapshot="active",
            version="v1",
            manifest_sha256="manifest",
            source_signature="signature",
            source_payload={},
            projected_payload={
                "x402Version": 2,
                "items": [
                    {
                        "resource": RESOURCE,
                        "type": "http",
                        "accepts": [REQUIREMENT],
                        "extensions": EXTENSION,
                    }
                ],
            },
            resource_count=1,
            status=BazaarCatalogSnapshot.Status.ACTIVE,
            fetched_at=timezone.now(),
            activated_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )

        response = self.client.get("/discovery/resources?extensions=bazaar&network=eip155:8453")

        assert response.status_code == 200
        assert response.json()["pagination"]["total"] == 1
        assert response.json()["items"][0]["resource"] == RESOURCE

    def test_payment_extension_must_match_active_snapshot(self) -> None:
        BazaarCatalogSnapshot.objects.create(
            snapshot="active",
            version="v1",
            manifest_sha256="manifest",
            source_signature="signature",
            source_payload={},
            projected_payload={
                "x402Version": 2,
                "items": [{"resource": RESOURCE, "accepts": [REQUIREMENT], "extensions": EXTENSION}],
            },
            resource_count=1,
            status=BazaarCatalogSnapshot.Status.ACTIVE,
            fetched_at=timezone.now(),
            activated_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        payload = SimpleNamespace(resource=SimpleNamespace(url=RESOURCE), extensions=deepcopy(EXTENSION))
        requirements = SimpleNamespace(model_dump=lambda **_kwargs: deepcopy(REQUIREMENT))

        bazaar.validate_payment_discovery(payload, requirements)
        payload.extensions["bazaar"]["info"]["input"]["body"]["query"] = "tampered"
        with pytest.raises(bazaar.BazaarCatalogError, match="does not match"):
            bazaar.validate_payment_discovery(payload, requirements)
