from django.contrib import admin

from x402f.models import X402Authorization


@admin.register(X402Authorization)
class X402AuthorizationAdmin(admin.ModelAdmin):
    list_display = ("nonce", "payer", "pay_to", "status", "transaction_hash", "created_at")
    list_filter = ("status",)
    search_fields = ("nonce", "payer", "pay_to", "transaction_hash")
