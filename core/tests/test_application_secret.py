import runpy
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

SETTINGS = Path(__file__).resolve().parents[2] / "core/settings.py"


def test_application_key_is_independent_of_obsolete_names(monkeypatch):
    monkeypatch.setenv("APPLICATION_SECRET_KEY", "current-application-key-for-test")
    for name in (
        "APP_SECRET_KEY",
        "AUTH_DJANGO_SECRET_KEY",
        "PLATFORM_DJANGO_SECRET_KEY",
        "GITHUB_CENTER_DJANGO_SECRET_KEY",
    ):
        monkeypatch.setenv(name, "obsolete-shared-value-for-test")
    monkeypatch.setenv("APP_ENV", "production")

    assert runpy.run_path(str(SETTINGS))["SECRET_KEY"] == "current-application-key-for-test"


def test_production_cannot_fall_back_to_obsolete_names(monkeypatch):
    monkeypatch.delenv("APPLICATION_SECRET_KEY", raising=False)
    for name in (
        "APP_SECRET_KEY",
        "AUTH_DJANGO_SECRET_KEY",
        "PLATFORM_DJANGO_SECRET_KEY",
        "GITHUB_CENTER_DJANGO_SECRET_KEY",
    ):
        monkeypatch.setenv(name, "obsolete-shared-value-for-test")
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(ImproperlyConfigured, match="application|APPLICATION|Independent"):
        runpy.run_path(str(SETTINGS))
