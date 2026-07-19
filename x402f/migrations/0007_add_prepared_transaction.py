from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("x402f", "0006_expand_official_signature")]

    operations = [
        migrations.AddField(
            model_name="x402authorization",
            name="prepared_transaction",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="x402authorization",
            name="signer_nonce",
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="x402authorization",
            name="transaction_broadcast_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
