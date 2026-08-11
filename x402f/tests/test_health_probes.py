"""Health probe tests. They live here because CI only runs `x402f/tests`."""

from unittest.mock import patch

from django.test import TestCase


class HealthProbeTests(TestCase):
    def test_healthz_is_static_and_never_touches_the_database(self) -> None:
        with patch("core.views.connection") as connection:
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        connection.cursor.assert_not_called()

    def test_healthz_db_reports_ok_when_database_is_reachable(self) -> None:
        response = self.client.get("/healthz/db")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "database": "ok"})

    def test_healthz_db_returns_503_when_database_is_unreachable(self) -> None:
        with patch("core.views.connection.cursor", side_effect=RuntimeError("could not translate host name")):
            response = self.client.get("/healthz/db")
        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["database"], "unavailable")
        self.assertIn("could not translate host name", payload["detail"])
