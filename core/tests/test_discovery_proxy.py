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
