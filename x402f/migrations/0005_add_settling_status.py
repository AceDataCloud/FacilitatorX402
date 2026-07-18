from django.db import migrations, models
from django.db.models import F


def backfill_settlement_leases(apps, schema_editor):  # noqa: ARG001, ANN001
    authorization = apps.get_model("x402f", "X402Authorization")
    authorization.objects.filter(status="settling", settling_started_at__isnull=True).update(
        settling_started_at=F("updated_at")
    )


class Migration(migrations.Migration):
    dependencies = [("x402f", "0004_upto_scheme_fields")]

    operations = [
        migrations.AlterField(
            model_name="x402authorization",
            name="status",
            field=models.CharField(
                choices=[
                    ("verified", "Verified"),
                    ("settling", "Settling"),
                    ("settled", "Settled"),
                    ("failed", "Failed"),
                ],
                default="verified",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="x402authorization",
            name="settling_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_settlement_leases, migrations.RunPython.noop),
    ]
