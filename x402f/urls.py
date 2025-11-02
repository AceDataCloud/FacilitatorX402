from django.urls import path

from x402f.views import X402SettleView, X402VerifyView

app_name = 'x402'

urlpatterns = [
    path('verify', X402VerifyView.as_view(), name='verify'),
    path('settle', X402SettleView.as_view(), name='settle'),
]
