from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("x402f", "0003_expand_transaction_hash"),
    ]

    operations = [
        migrations.AddField(
            model_name="x402authorization",
            name="scheme",
            field=models.CharField(default="exact", max_length=32),
        ),
        migrations.AddField(
            model_name="x402authorization",
            name="settled_amount",
            field=models.CharField(blank=True, max_length=78, null=True),
        ),
        migrations.AlterField(
            model_name="x402authorization",
            name="nonce",
            field=models.CharField(max_length=128, unique=True),
        ),
    ]
