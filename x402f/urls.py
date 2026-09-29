from django.urls import path

from x402f.views_official import X402SettleView, X402SupportedView, X402VerifyView

app_name = "x402"

urlpatterns = [
    path("supported", X402SupportedView.as_view(), name="supported"),
    path("verify", X402VerifyView.as_view(), name="verify"),
    path("settle", X402SettleView.as_view(), name="settle"),
]
