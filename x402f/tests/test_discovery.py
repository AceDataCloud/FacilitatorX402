"""Tests for x402 discovery resource enumeration."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from django.test import RequestFactory

from x402f.discovery import _build_accepts, discovery_list_redirect, discovery_resources


def _decode(response):
    return json.loads(response.content.decode("utf-8"))


def _stub_upstream(urls):
    fake = mock.Mock()
    fake.json.return_value = {"version": 1, "resources": urls}
    fake.raise_for_status.return_value = None
    return fake


@pytest.fixture(autouse=True)
def _clear_cache():
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


def test_build_accepts_includes_all_configured_networks(monkeypatch):
    monkeypatch.setenv("X402_BASE_PAY_TO", "0x4F0E2D3477a1B94CF33d16E442CEe4733dadCeE7")
    monkeypatch.setenv("X402_SOLANA_PAY_TO", "5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43")
    monkeypatch.setenv("X402_SKALE_PAY_TO", "0x1111111111111111111111111111111111111111")

    accepts = _build_accepts()

    networks = {a["network"] for a in accepts}
    assert networks == {"base", "solana", "skale"}
    for a in accepts:
        assert a["scheme"] == "exact"
        assert a["maxAmountRequired"] == "0"
        assert a["asset"]


def test_build_accepts_skips_networks_without_pay_to(monkeypatch):
    monkeypatch.setenv("X402_BASE_PAY_TO", "")
    monkeypatch.setenv("X402_SOLANA_PAY_TO", "5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43")
    monkeypatch.setenv("X402_SKALE_PAY_TO", "")

    accepts = _build_accepts()

    assert [a["network"] for a in accepts] == ["solana"]


def test_discovery_resources_paginates_and_embeds_accepts(monkeypatch):
    monkeypatch.setenv("X402_BASE_PAY_TO", "0x4F0E2D3477a1B94CF33d16E442CEe4733dadCeE7")
    monkeypatch.setenv("X402_SOLANA_PAY_TO", "5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43")
    monkeypatch.setenv("X402_SKALE_PAY_TO", "")

    urls = [f"https://api.acedata.cloud/svc/{i}" for i in range(5)]
    with mock.patch("x402f.discovery.requests.get", return_value=_stub_upstream(urls)):
        request = RequestFactory().get("/discovery/resources?limit=2&offset=1")
        response = discovery_resources(request)

    assert response.status_code == 200
    body = _decode(response)
    assert body["x402Version"] == 2
    assert body["pagination"] == {"limit": 2, "offset": 1, "total": 5}
    assert len(body["items"]) == 2

    item = body["items"][0]
    assert item["resource"] == urls[1]
    networks = {a["network"] for a in item["accepts"]}
    assert networks == {"base", "solana"}
    assert all(a["resource"] == urls[1] for a in item["accepts"])
    assert all("AceDataCloud API:" in a["description"] for a in item["accepts"])


def test_discovery_returns_empty_items_when_no_pay_to_configured(monkeypatch):
    for var in ("X402_BASE_PAY_TO", "X402_SOLANA_PAY_TO", "X402_SKALE_PAY_TO"):
        monkeypatch.setenv(var, "")

    request = RequestFactory().get("/discovery/resources")
    response = discovery_resources(request)

    assert response.status_code == 200
    body = _decode(response)
    assert body["items"] == []
    assert body["pagination"]["total"] == 0


def test_discovery_swallows_upstream_failure(monkeypatch):
    monkeypatch.setenv("X402_BASE_PAY_TO", "0x4F0E2D3477a1B94CF33d16E442CEe4733dadCeE7")
    monkeypatch.setenv("X402_SOLANA_PAY_TO", "")
    monkeypatch.setenv("X402_SKALE_PAY_TO", "")

    with mock.patch("x402f.discovery.requests.get", side_effect=RuntimeError("boom")):
        request = RequestFactory().get("/discovery/resources")
        response = discovery_resources(request)

    assert response.status_code == 200
    assert _decode(response)["items"] == []


def test_discovery_list_redirect_preserves_query_string():
    request = RequestFactory().get("/list?limit=20&offset=40")
    response = discovery_list_redirect(request)

    assert response.status_code == 308
    assert response["Location"] == "/discovery/resources?limit=20&offset=40"
