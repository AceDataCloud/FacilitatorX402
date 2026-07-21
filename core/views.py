import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpResponse, HttpResponsePermanentRedirect, JsonResponse
from x402.mechanisms.svm.constants import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2

from x402f.official import SKALE_MAINNET

NETWORK_TO_CAIP2 = {
    "base": "eip155:8453",
    "solana": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana-devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
}
MAX_DISCOVERY_BYTES = 5 * 1024 * 1024


def _discovery_accepts() -> list[dict]:
    accepts = []

    def add(scheme: str, network: str, asset: str, pay_to: str, extra: dict) -> None:
        if not asset or not pay_to:
            return
        accepts.append(
            {
                "scheme": scheme,
                "network": network,
                "asset": asset,
                "payTo": pay_to,
                "maxAmountRequired": "0",
                "maxTimeoutSeconds": 120,
                "mimeType": "application/json",
                "extra": extra,
            }
        )

    base_extra = {
        "chainId": settings.X402_BASE_CHAIN_ID,
        "name": "USD Coin",
        "version": "2",
        "verifyingContract": settings.X402_BASE_ASSET,
    }
    if settings.X402_BASE_EXACT_ENABLED:
        add("exact", settings.X402_BASE_NETWORK, settings.X402_BASE_ASSET, settings.X402_BASE_PAY_TO, base_extra)
    if settings.X402_BASE_UPTO_ENABLED and settings.X402_BASE_SIGNER_ADDRESS:
        add(
            "upto",
            settings.X402_BASE_NETWORK,
            settings.X402_BASE_ASSET,
            settings.X402_BASE_PAY_TO,
            {
                "chainId": settings.X402_BASE_CHAIN_ID,
                "facilitatorAddress": settings.X402_BASE_SIGNER_ADDRESS,
                "name": "Permit2",
            },
        )
    if settings.X402_SKALE_EXACT_ENABLED:
        add(
            "exact",
            SKALE_MAINNET,
            settings.X402_SKALE_ASSET,
            settings.X402_SKALE_PAY_TO,
            {
                "chainId": settings.X402_SKALE_CHAIN_ID,
                "name": "Bridged USDC (SKALE Bridge)",
                "version": "2",
                "verifyingContract": settings.X402_SKALE_ASSET,
            },
        )
    if settings.X402_SOLANA_MAINNET_ENABLED and settings.X402_SOLANA_SIGNER_ADDRESS:
        add(
            "exact",
            SOLANA_MAINNET_CAIP2,
            settings.X402_SOLANA_ASSET,
            settings.X402_SOLANA_PAY_TO,
            {"decimals": 6, "feePayer": settings.X402_SOLANA_SIGNER_ADDRESS},
        )
    return accepts


def _valid_discovery_resource(resource: object) -> bool:
    if not isinstance(resource, str):
        return False
    parsed = urlsplit(resource)
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.hostname.lower() in settings.X402_DISCOVERY_RESOURCE_HOSTS
    )


def _valid_discovery_catalog(data: dict) -> bool:
    items = data.get("items")
    if data.get("x402Version") != 2 or not isinstance(items, list) or not isinstance(data.get("pagination"), dict):
        return False
    resources = []
    for item in items:
        if not isinstance(item, dict) or not _valid_discovery_resource(item.get("resource")):
            return False
        resource = item["resource"]
        accepts = item.get("accepts")
        if not isinstance(accepts, list):
            return False
        if any(not isinstance(value, dict) or value.get("resource", resource) != resource for value in accepts):
            return False
        resources.append(resource)
    return len(resources) == len(set(resources))


def _catalog_from_resources(data: dict, request) -> dict | None:  # noqa: ANN001
    resources = data.get("resources")
    if data.get("version") != 1 or not isinstance(resources, list):
        return None
    allowed_hosts = settings.X402_DISCOVERY_RESOURCE_HOSTS
    if not allowed_hosts or not resources:
        return None
    normalized = []
    for resource in resources:
        if not _valid_discovery_resource(resource):
            return None
        normalized.append(resource)
    if len(normalized) != len(set(normalized)):
        return None
    try:
        limit = max(1, min(int(request.GET.get("limit", "100")), 500))
        offset = max(0, int(request.GET.get("offset", "0")))
    except (TypeError, ValueError):
        limit, offset = 100, 0
    accepts = _discovery_accepts()
    last_updated = datetime.now(timezone.utc).isoformat()
    items = []
    for resource in normalized[offset : offset + limit]:
        path = urlsplit(resource).path or "/"
        resource_accepts = []
        for requirement in accepts:
            value = dict(requirement)
            value["resource"] = resource
            value["description"] = f"AceDataCloud API: {path}"
            resource_accepts.append(value)
        items.append(
            {
                "resource": resource,
                "type": "http",
                "x402Version": 2,
                "accepts": resource_accepts,
                "lastUpdated": last_updated,
                "metadata": None,
            }
        )
    return {
        "x402Version": 2,
        "items": items,
        "pagination": {"limit": limit, "offset": offset, "total": len(normalized)},
    }


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


HOME_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Ace Data Cloud · Facilitator X402</title>
<style>
    :root {
        font-family: "Space Grotesk", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: #0f172a;
        background: radial-gradient(circle at top, #eff6ff, #ffffff 45%);
    }
    body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .hero {
        width: min(960px, 92vw);
        padding: 3rem 3.5rem;
        border-radius: 32px;
        background: rgba(255, 255, 255, 0.9);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
        border: 1px solid rgba(59, 130, 246, 0.15);
    }
    .eyebrow {
        text-transform: uppercase;
        font-size: 0.85rem;
        letter-spacing: 0.2em;
        color: #2563eb;
        font-weight: 600;
    }
    h1 {
        font-size: clamp(2.5rem, 4vw, 3.75rem);
        margin: 0.25rem 0 1rem;
    }
    p.lead {
        font-size: 1.15rem;
        line-height: 1.6;
        max-width: 58ch;
    }
    .cta-row {
        margin-top: 2rem;
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .cta {
        flex: 1 1 240px;
        padding: 1.25rem;
        border-radius: 18px;
        border: 1px solid rgba(15, 23, 42, 0.08);
        background: #f8fafc;
    }
    .cta h2 {
        margin: 0 0 0.35rem;
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #475569;
    }
    code {
        font-size: 0.95rem;
        background: rgba(59, 130, 246, 0.1);
        padding: 0.4rem 0.6rem;
        border-radius: 8px;
        display: inline-block;
    }
    @media (max-width: 640px) {
        .hero {
            padding: 2.5rem 1.75rem;
        }
    }
</style>
</head>
<body>
    <main class="hero">
        <div class="eyebrow">Ace Data Cloud</div>
        <h1>Facilitator X402</h1>
        <p class="lead">
            Production-grade settlement for x402 micropayments. Verify signed authorizations,
            settle stablecoin transfers on-chain, and unlock pay-per-request APIs with a single call.
        </p>
        <div class="cta-row">
            <div class="cta">
                <h2>Verify</h2>
                <p>Validate payload integrity, enforce quotas, and stage the nonce.</p>
                <code>POST /verify</code>
            </div>
            <div class="cta">
                <h2>Settle</h2>
                <p>Submit the stored authorization to the chain and receive the receipt.</p>
                <code>POST /settle</code>
            </div>
        </div>
    </main>
</body>
</html>"""


def home(request):
    return HttpResponse(HOME_PAGE_HTML, content_type="text/html; charset=utf-8")


def health(request):
    return JsonResponse({"status": "ok"})


def build_well_known_x402_data(facilitator_url: str) -> dict:
    """Build machine-readable facilitator metadata for /.well-known/x402."""
    supported_kinds = []
    supported_networks = []
    addresses = {}

    def add_kind(scheme: str, network: str) -> None:
        supported_kinds.append({"x402Version": 2, "scheme": scheme, "network": network})

    if settings.X402_BASE_EXACT_ENABLED:
        add_kind("exact", settings.X402_BASE_NETWORK)
    if settings.X402_BASE_UPTO_ENABLED:
        add_kind("upto", settings.X402_BASE_NETWORK)
    if settings.X402_BASE_EXACT_ENABLED or settings.X402_BASE_UPTO_ENABLED:
        supported_networks.append({"network": "base", "caip2": settings.X402_BASE_NETWORK})
        if settings.X402_BASE_SIGNER_ADDRESS:
            addresses["base"] = settings.X402_BASE_SIGNER_ADDRESS
    if settings.X402_SKALE_EXACT_ENABLED:
        add_kind("exact", SKALE_MAINNET)
        supported_networks.append({"network": "skale", "caip2": SKALE_MAINNET})
        if settings.X402_SKALE_SIGNER_ADDRESS:
            addresses["skale"] = settings.X402_SKALE_SIGNER_ADDRESS
    if settings.X402_SOLANA_MAINNET_ENABLED:
        add_kind("exact", SOLANA_MAINNET_CAIP2)
        supported_networks.append({"network": "solana", "caip2": SOLANA_MAINNET_CAIP2})
        if settings.X402_SOLANA_SIGNER_ADDRESS:
            addresses["solana"] = settings.X402_SOLANA_SIGNER_ADDRESS
    if settings.X402_SOLANA_DEVNET_ENABLED:
        add_kind("exact", SOLANA_DEVNET_CAIP2)
        supported_networks.append({"network": "solana-devnet", "caip2": SOLANA_DEVNET_CAIP2})

    data = {
        # Compatibility shape for discovery clients. Facilitators do not expose
        # paid resources here, so the list intentionally remains empty.
        "version": 2,
        "resources": [],
        "instructions": (
            "This origin is an x402 facilitator. Use /supported, /verify, and /settle "
            "instead of treating it as a paid resource server."
        ),
        "facilitator": {
            "name": "Ace Data Cloud Facilitator X402",
            "url": facilitator_url,
            "description": "Production settlement and verification service for Ace Data Cloud x402 payments.",
            "supportedKinds": supported_kinds,
            "supportedNetworks": supported_networks,
            "supportedCurrencies": ["USDC"],
            "endpoints": {
                "supported": f"{facilitator_url}/supported",
                "verify": f"{facilitator_url}/verify",
                "settle": f"{facilitator_url}/settle",
            },
            "addresses": addresses,
        },
    }
    return data


def well_known_x402(request):
    """Machine-readable facilitator metadata endpoint (/.well-known/x402)."""
    facilitator_url = settings.X402_FACILITATOR_PUBLIC_URL.rstrip("/") or request.build_absolute_uri("/").rstrip("/")
    return JsonResponse(build_well_known_x402_data(facilitator_url))


def discovery_resources(request):  # noqa: ANN001
    url = settings.X402_DISCOVERY_URL
    parsed = urlsplit(url)
    allowed_hosts = settings.X402_DISCOVERY_ALLOWED_HOSTS
    request_host = request.get_host().split(":", 1)[0].lower()
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.hostname.lower() not in allowed_hosts
        or parsed.hostname.lower() == request_host
    ):
        return JsonResponse({"error": "Resource discovery is unavailable."}, status=503)
    try:
        opener = urllib.request.build_opener(NoRedirectHandler())
        with opener.open(url, timeout=10) as response:
            raw = response.read(MAX_DISCOVERY_BYTES + 1)
        if len(raw) > MAX_DISCOVERY_BYTES:
            raise ValueError("discovery response is too large")
        data = json.loads(raw)
    except (OSError, ValueError, urllib.error.URLError):
        return JsonResponse({"error": "Resource discovery is unavailable."}, status=503)
    if not isinstance(data, dict):
        return JsonResponse({"error": "Resource discovery returned an invalid response."}, status=503)
    if {"x402Version", "items", "pagination"}.issubset(data):
        if _valid_discovery_catalog(data):
            return JsonResponse(data)
        return JsonResponse({"error": "Resource discovery returned an invalid response."}, status=503)
    catalog = _catalog_from_resources(data, request)
    if catalog is None:
        return JsonResponse({"error": "Resource discovery returned an invalid response."}, status=503)
    return JsonResponse(catalog)


def discovery_list(request):  # noqa: ANN001
    return HttpResponsePermanentRedirect("/discovery/resources")
