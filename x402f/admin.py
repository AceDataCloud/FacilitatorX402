from django.contrib import admin

from x402f.models import BazaarCatalogSnapshot, X402Authorization


@admin.register(BazaarCatalogSnapshot)
class BazaarCatalogSnapshotAdmin(admin.ModelAdmin):
    list_display = ("snapshot", "status", "resource_count", "fetched_at", "activated_at", "expires_at")
    list_filter = ("status",)
    search_fields = ("snapshot", "manifest_sha256")
    readonly_fields = ("source_payload", "projected_payload")


@admin.register(X402Authorization)
class X402AuthorizationAdmin(admin.ModelAdmin):
    list_display = ("nonce", "payer", "pay_to", "status", "transaction_hash", "created_at")
    list_filter = ("status",)
    search_fields = ("nonce", "payer", "pay_to", "transaction_hash")
