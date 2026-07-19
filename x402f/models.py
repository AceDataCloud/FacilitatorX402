from django.db import models
from django.utils import timezone


class X402Authorization(models.Model):
    class Status(models.TextChoices):
        VERIFIED = "verified", "Verified"
        SETTLING = "settling", "Settling"
        SETTLED = "settled", "Settled"
        FAILED = "failed", "Failed"

    nonce = models.CharField(max_length=128, unique=True)
    # Multi-chain support: EVM addresses (42 chars) + Solana (base58 ~44 chars) + future chains
    payer = models.CharField(max_length=128)
    pay_to = models.CharField(max_length=128)
    value = models.CharField(max_length=78)
    valid_after = models.DateTimeField()
    valid_before = models.DateTimeField()
    signature = models.TextField()
    payment_requirements = models.JSONField()
    payment_payload = models.JSONField()
    scheme = models.CharField(max_length=32, default="exact")
    # For upto: settled_amount may differ from `value` (the signed ceiling).
    settled_amount = models.CharField(max_length=78, blank=True, null=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.VERIFIED,
    )
    # EVM tx hash is 66 chars (0x + 64 hex); Solana signature is base58 (~88 chars).
    transaction_hash = models.CharField(max_length=128, blank=True, null=True)
    prepared_transaction = models.TextField(blank=True, null=True)
    signer_nonce = models.BigIntegerField(blank=True, null=True)
    transaction_broadcast_at = models.DateTimeField(blank=True, null=True)
    settled_at = models.DateTimeField(blank=True, null=True)
    settling_started_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def mark_settled(self, tx_hash: str, settled_amount: str | None = None) -> None:
        self.status = self.Status.SETTLED
        self.transaction_hash = tx_hash
        self.settled_at = timezone.now()
        self.settling_started_at = None
        if settled_amount is not None:
            self.settled_amount = str(settled_amount)
