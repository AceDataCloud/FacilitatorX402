"""core URL Configuration."""

from django.contrib import admin
from django.urls import include, path, re_path

from core.views import health, home, well_known_x402

urlpatterns = [
    path("", home, name="home"),
    path("healthz", health, name="healthz"),
    re_path(r"^\.well-known/x402/?$", well_known_x402, name="well-known-x402"),
    path("", include("x402f.urls", namespace="x402")),
    path("admin/", admin.site.urls),
]
