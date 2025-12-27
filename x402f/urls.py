from django.urls import path

# Use multi-chain views for dynamic network support
from x402f.views_multichain import X402SettleView, X402VerifyView, X402SupportedView

# Legacy single-chain views (for reference)
# from x402f.views import X402SettleView, X402VerifyView

app_name = 'x402'

urlpatterns = [
    path('supported', X402SupportedView.as_view(), name='supported'),
    path('verify', X402VerifyView.as_view(), name='verify'),
    path('settle', X402SettleView.as_view(), name='settle'),
]
