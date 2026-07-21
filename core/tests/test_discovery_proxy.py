import json
from unittest.mock import patch

from django.test import TestCase, override_settings


class Response:
    def __init__(self, value):  # noqa: ANN001
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _size=-1):
        return self.value if isinstance(self.value, bytes) else json.dumps(self.value).encode()


class DiscoveryProxyTests(TestCase):
    def test_list_redirects_to_discovery(self) -> None:
        response = self.client.get("/list")
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response.headers["Location"], "/discovery/resources")

    @override_settings(X402_DISCOVERY_URL="")
    def test_missing_discovery_source_fails_closed(self) -> None:
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)

    @override_settings(
        X402_DISCOVERY_URL="https://x402.acedata.cloud/discovery/resources",
        X402_DISCOVERY_ALLOWED_HOSTS=("x402.acedata.cloud",),
    )
    @patch("core.views.urllib.request.build_opener")
    def test_discovery_proxy_validates_and_returns_catalog(self, build_opener) -> None:
        opener = build_opener.return_value
        catalog = {"x402Version": 2, "items": [], "pagination": {"total": 0}}
        opener.open.return_value = Response(catalog)
        response = self.client.get("/discovery/resources")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), catalog)

        opener.open.return_value = Response({"items": []})
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)

        opener.open.return_value = Response(b"x" * (5 * 1024 * 1024 + 1))
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)

    @override_settings(
        X402_DISCOVERY_URL="https://attacker.example/resources",
        X402_DISCOVERY_ALLOWED_HOSTS=("x402.acedata.cloud",),
    )
    def test_discovery_rejects_unapproved_host(self) -> None:
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)

    @override_settings(
        X402_DISCOVERY_URL="https://platform.acedata.cloud/api/v1/x402/discovery/",
        X402_DISCOVERY_ALLOWED_HOSTS=("platform.acedata.cloud",),
        X402_DISCOVERY_RESOURCE_HOSTS=("x402.acedata.cloud",),
        X402_BASE_NETWORK="eip155:8453",
        X402_BASE_ASSET="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        X402_BASE_PAY_TO="0x1111111111111111111111111111111111111111",
        X402_BASE_SIGNER_ADDRESS="0x2222222222222222222222222222222222222222",
        X402_BASE_EXACT_ENABLED=True,
        X402_BASE_UPTO_ENABLED=True,
        X402_SKALE_ASSET="0x85889c8c714505E0c94b30fcfcF64fE3Ac8FCb20",
        X402_SKALE_PAY_TO="0x1111111111111111111111111111111111111111",
        X402_SKALE_EXACT_ENABLED=True,
        X402_SOLANA_ASSET="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        X402_SOLANA_PAY_TO="5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43",
        X402_SOLANA_SIGNER_ADDRESS="3SPm6qbgsDkj24MuR8Ss4sH97fziqyCiqFKDyeVU2igq",
        X402_SOLANA_MAINNET_ENABLED=True,
    )
    @patch("core.views.urllib.request.build_opener")
    def test_discovery_builds_caip2_catalog_from_resource_source(self, build_opener) -> None:
        resources = [f"https://x402.acedata.cloud/service/{index}" for index in range(3)]
        build_opener.return_value.open.return_value = Response({"version": 1, "resources": resources})

        response = self.client.get("/discovery/resources?limit=1&offset=1")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["pagination"], {"limit": 1, "offset": 1, "total": 3})
        self.assertEqual(data["items"][0]["resource"], resources[1])
        self.assertEqual(data["items"][0]["type"], "http")
        self.assertEqual(data["items"][0]["x402Version"], 2)
        self.assertEqual(
            {(item["scheme"], item["network"]) for item in data["items"][0]["accepts"]},
            {
                ("exact", "eip155:8453"),
                ("upto", "eip155:8453"),
                ("exact", "eip155:1187947933"),
                ("exact", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            },
        )

    @override_settings(
        X402_DISCOVERY_URL="https://facilitator.acedata.cloud/discovery/resources",
        X402_DISCOVERY_ALLOWED_HOSTS=("facilitator.acedata.cloud",),
    )
    def test_discovery_rejects_recursive_source(self) -> None:
        response = self.client.get("/discovery/resources", HTTP_HOST="facilitator.acedata.cloud")
        self.assertEqual(response.status_code, 503)

    @override_settings(
        X402_DISCOVERY_URL="https://platform.acedata.cloud/api/v1/x402/discovery/",
        X402_DISCOVERY_ALLOWED_HOSTS=("platform.acedata.cloud",),
        X402_DISCOVERY_RESOURCE_HOSTS=("x402.acedata.cloud",),
    )
    @patch("core.views.urllib.request.build_opener")
    def test_discovery_rejects_unapproved_resource_host(self, build_opener) -> None:
        build_opener.return_value.open.return_value = Response(
            {"version": 1, "resources": ["https://attacker.example/paid"]}
        )
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)

    @override_settings(
        X402_DISCOVERY_URL="https://platform.acedata.cloud/discovery/resources",
        X402_DISCOVERY_ALLOWED_HOSTS=("platform.acedata.cloud",),
        X402_DISCOVERY_RESOURCE_HOSTS=("x402.acedata.cloud",),
    )
    @patch("core.views.urllib.request.build_opener")
    def test_discovery_validates_resource_hosts_in_v2_catalog(self, build_opener) -> None:
        opener = build_opener.return_value
        opener.open.return_value = Response(
            {
                "x402Version": 2,
                "items": [
                    {
                        "resource": "https://attacker.example/paid",
                        "accepts": [],
                    }
                ],
                "pagination": {"limit": 1, "offset": 0, "total": 1},
            }
        )
        self.assertEqual(self.client.get("/discovery/resources").status_code, 503)
