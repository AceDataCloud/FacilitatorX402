"""x402 core-v2 conformance regression (ported from the retired X402Backend).

The pinned manifest (`profiles/core-v2/2026-07-19/manifest.json`, 53 cases,
official spec commit 67b1ba0a...) is the industry-standard contract for an x402
v2 facilitator's /supported, /verify and /settle endpoints.

This module runs the 14 deterministic `supported` cases directly against the
live `X402SupportedView` — they need no signed fixtures, so they make a clean CI
regression guard that the facilitator's advertised capabilities stay V2-shaped
(CAIP-2 networks, integer x402Version, no short-network names, no secret leakage).

The 26 `verify` and 13 `settle` cases require signed EIP-3009 / SPL fixtures and
are covered by the signing/settlement tests in this package; the manifest is
committed here as the pinned reference for that fixture-driven follow-up.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from django.test import TestCase
from django.urls import reverse

MANIFEST = (
    Path(__file__).resolve().parent.parent / "conformance" / "profiles" / "core-v2" / "2026-07-19" / "manifest.json"
)

_SHORT_NETWORKS = {"base", "solana", "skale"}
_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_SECRET_KEY = re.compile(r"(?:secret|api[_-]?key|token|authorization|private|mnemonic)", re.IGNORECASE)


def _is_caip2(value: Any) -> bool:
    return isinstance(value, str) and _CAIP2.fullmatch(value) is not None


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_SECRET_KEY.search(str(key)) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


# The 14 deterministic /supported checks, ported verbatim from the X402Backend
# conformance runner. Each maps a manifest case id -> predicate over the body.
SUPPORTED_CHECKS = {
    "supported_status_200": lambda status, body: status == 200,
    "supported_json_content_type": lambda status, body: True,  # asserted separately via response header
    "supported_body_object": lambda status, body: isinstance(body, dict),
    "supported_kinds_array": lambda status, body: isinstance(body.get("kinds"), list),
    "supported_nonempty": lambda status, body: bool(body.get("kinds")),
    "supported_kind_object": lambda status, body: all(isinstance(i, dict) for i in body.get("kinds", [])),
    "supported_version_integer": lambda status, body: all(i.get("x402Version") == 2 for i in body.get("kinds", [])),
    "supported_scheme_string": lambda status, body: all(
        isinstance(i.get("scheme"), str) for i in body.get("kinds", [])
    ),
    "supported_exact": lambda status, body: any(i.get("scheme") == "exact" for i in body.get("kinds", [])),
    "supported_network_string": lambda status, body: all(
        isinstance(i.get("network"), str) for i in body.get("kinds", [])
    ),
    "supported_network_caip2": lambda status, body: all(_is_caip2(i.get("network")) for i in body.get("kinds", [])),
    "supported_no_short_network": lambda status, body: all(
        i.get("network") not in _SHORT_NETWORKS for i in body.get("kinds", [])
    ),
    "supported_unique_kinds": lambda status, body: (
        len({(i.get("scheme"), i.get("network")) for i in body.get("kinds", [])}) == len(body.get("kinds", []))
    ),
    "supported_no_secrets": lambda status, body: not _contains_secret(body),
}


class ConformanceManifestTests(TestCase):
    def test_manifest_is_the_pinned_core_v2_contract(self) -> None:
        manifest = json.loads(MANIFEST.read_text())
        assert manifest["profile"] == "core-v2"
        assert manifest["official_spec_commit"] == "67b1ba0a7abbd7907a28fa624670872532e0eae9"
        assert len(manifest["cases"]) == 53
        by_endpoint: dict[str, int] = {}
        for case in manifest["cases"]:
            by_endpoint[case["fixture"]["endpoint"]] = by_endpoint.get(case["fixture"]["endpoint"], 0) + 1
        assert by_endpoint == {"supported": 14, "verify": 26, "settle": 13}

    def test_manifest_covers_every_implemented_supported_check(self) -> None:
        """Guard against a manifest case whose check has no ported predicate."""
        manifest = json.loads(MANIFEST.read_text())
        supported_ids = {c["check"] for c in manifest["cases"] if c["fixture"]["endpoint"] == "supported"}
        assert supported_ids == set(SUPPORTED_CHECKS), (
            "supported checks drifted from the manifest",
            supported_ids ^ set(SUPPORTED_CHECKS),
        )


class SupportedConformanceTests(TestCase):
    def test_supported_endpoint_passes_all_14_static_cases(self) -> None:
        response = self.client.get(reverse("x402:supported"))
        assert response["Content-Type"].split(";")[0] == "application/json"
        body = response.json()
        failures = [
            check_id for check_id, predicate in SUPPORTED_CHECKS.items() if not predicate(response.status_code, body)
        ]
        assert not failures, f"/supported failed conformance checks: {failures} (body={body})"
