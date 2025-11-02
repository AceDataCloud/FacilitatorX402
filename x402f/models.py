from django.db import models
from django.utils import timezone


class X402Authorization(models.Model):
    class Status(models.TextChoices):
        VERIFIED = 'verified', 'Verified'
        SETTLED = 'settled', 'Settled'

    nonce = models.CharField(max_length=66, unique=True)
    payer = models.CharField(max_length=42)
    pay_to = models.CharField(max_length=42)
    value = models.CharField(max_length=78)
    valid_after = models.DateTimeField()
    valid_before = models.DateTimeField()
    signature = models.CharField(max_length=132)
    payment_requirements = models.JSONField()
    payment_payload = models.JSONField()
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.VERIFIED,
    )
    transaction_hash = models.CharField(max_length=66, blank=True, null=True)
    settled_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def mark_settled(self, tx_hash: str) -> None:
        self.status = self.Status.SETTLED
        self.transaction_hash = tx_hash
        self.settled_at = timezone.now()
