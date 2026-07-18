"""x402 discovery resource enumeration.

Exposes ``/discovery/resources`` (and a ``308`` redirect from ``/list``)
so that crawlers such as x402scan can pick up the paid APIs the
upstream resource server publishes via ``/.well-known/x402``. Schema
follows the convention used by other public facilitators (payAI,
OpenFacilitator) — a paginated ``items[]`` list where each entry
embeds the standard ``accepts[]`` payment requirements per network.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List

import requests
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse

# Well-known USDC asset constants — same values used by PlatformBackend
# and by x402scan's own facilitator constants.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_SOLANA = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

DEFAULT_UPSTREAM_URL = "https://platform.acedata.cloud/.well-known/x402"
CACHE_KEY = "x402:discovery:items"
CACHE_TTL_SECONDS = 300


def _build_accepts() -> List[Dict[str, Any]]:
    base_pay_to = os.environ.get("X402_BASE_PAY_TO", "").strip()
    solana_pay_to = os.environ.get("X402_SOLANA_PAY_TO", "").strip()
    solana_fee_payer = os.environ.get("X402_SOLANA_SIGNER_ADDRESS", "").strip()

    accepts: List[Dict[str, Any]] = []

    if base_pay_to:
        accepts.append(
            {
                "scheme": "exact",
                "network": "base",
                "asset": os.environ.get("X402_BASE_ASSET", USDC_BASE),
                "payTo": base_pay_to,
                # Discovery items do not advertise a fixed price; the
                # actual amount is resolved at request time by the
                # gateway. Use "0" so clients probe the URL for the
                # real 402 challenge.
                "maxAmountRequired": "0",
                "maxTimeoutSeconds": 120,
                "mimeType": "application/json",
                "extra": {"decimals": 6, "name": "USD Coin", "version": "2"},
            }
        )

    if solana_pay_to:
        accepts.append(
            {
                "scheme": "exact",
                "network": "solana",
                "asset": os.environ.get("X402_SOLANA_ASSET", USDC_SOLANA),
                "payTo": solana_pay_to,
                "maxAmountRequired": "0",
                "maxTimeoutSeconds": 120,
                "mimeType": "application/json",
                "extra": {
                    "decimals": 6,
                    "feePayer": solana_fee_payer,
                    "computeUnitLimit": 100_000,
                    "computeUnitPriceMicroLamports": 5_000,
                },
            }
        )

    # SKALE Europa Hub mainnet (chainId 2046399126) is supported by our
    # facilitator's /supported and /verify endpoints, but the x402 SDK's
    # NetworkSchema enum (and consumers like x402scan) do not yet recognise
    # a "skale" network token, so emitting it here would cause downstream
    # zod validation to reject the entire accepts array (and drop every
    # resource). Omit SKALE from discovery until upstream support lands.

    return accepts


def _fetch_upstream_resources() -> List[str]:
    upstream = getattr(settings, "X402_DISCOVERY_UPSTREAM_URL", "") or DEFAULT_UPSTREAM_URL
    response = requests.get(upstream, timeout=10)
    response.raise_for_status()
    data = response.json() or {}
    resources = data.get("resources") or []
    return [str(r) for r in resources if isinstance(r, str) and r.startswith("http")]


def _build_items() -> List[Dict[str, Any]]:
    accepts = _build_accepts()
    if not accepts:
        return []

    try:
        resources = _fetch_upstream_resources()
    except Exception:
        # If upstream is briefly unavailable serve an empty list rather
        # than 5xx; crawlers will retry.
        return []

    last_updated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    items: List[Dict[str, Any]] = []
    for url in resources:
        path = url.split("//", 1)[-1].split("/", 1)
        nice_path = "/" + path[1] if len(path) == 2 else url

        per_resource_accepts = []
        for base in accepts:
            entry = dict(base)
            entry["resource"] = url
            entry["description"] = f"AceDataCloud API: {nice_path}"
            per_resource_accepts.append(entry)

        items.append(
            {
                "resource": url,
                "accepts": per_resource_accepts,
                "lastUpdated": last_updated,
                "metadata": None,
            }
        )

    return items


def discovery_resources(request):
    """Return paginated x402 resource discovery payload."""
    items = cache.get(CACHE_KEY)
    if items is None:
        items = _build_items()
        cache.set(CACHE_KEY, items, timeout=CACHE_TTL_SECONDS)

    try:
        limit = max(1, min(int(request.GET.get("limit", "100")), 500))
        offset = max(0, int(request.GET.get("offset", "0")))
    except (TypeError, ValueError):
        limit, offset = 100, 0

    page = items[offset : offset + limit]
    return JsonResponse(
        {
            "x402Version": 2,
            "items": page,
            "pagination": {"limit": limit, "offset": offset, "total": len(items)},
        }
    )


def discovery_list_redirect(request):
    """Convenience 308 redirect (mirrors payAI's behaviour)."""
    target = "/discovery/resources"
    if request.META.get("QUERY_STRING"):
        target = f"{target}?{request.META['QUERY_STRING']}"
    response = HttpResponse(status=308)
    response["Location"] = target
    return response
