from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="X402Authorization",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("nonce", models.CharField(max_length=66, unique=True)),
                ("payer", models.CharField(max_length=42)),
                ("pay_to", models.CharField(max_length=42)),
                ("value", models.CharField(max_length=78)),
                ("valid_after", models.DateTimeField()),
                ("valid_before", models.DateTimeField()),
                ("signature", models.CharField(max_length=132)),
                ("payment_requirements", models.JSONField()),
                ("payment_payload", models.JSONField()),
                (
                    "status",
                    models.CharField(
                        choices=[("verified", "Verified"), ("settled", "Settled")], default="verified", max_length=16
                    ),
                ),
                ("transaction_hash", models.CharField(blank=True, max_length=66, null=True)),
                ("settled_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
