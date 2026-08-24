from django.db import migrations, models
from django.db.models import Count, Q


def reject_duplicate_operations(apps, schema_editor):  # noqa: ANN001, ARG001
    authorization = apps.get_model("x402f", "X402Authorization")
    duplicate = (
        authorization.objects.filter(verification_id__isnull=False)
        .values("verification_id")
        .annotate(total=Count("id"))
        .filter(total__gt=1)
        .order_by("verification_id")
        .first()
    )
    if duplicate:
        raise RuntimeError(
            "Duplicate X402 verification operation ids must be reconciled before migration: "
            f"{duplicate['verification_id']} ({duplicate['total']} rows)"
        )


class Migration(migrations.Migration):
    dependencies = [("x402f", "0011_delete_bazaar_catalog_snapshot")]

    operations = [
        migrations.RunPython(reject_duplicate_operations, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="x402authorization",
            constraint=models.UniqueConstraint(
                fields=("verification_id",),
                condition=Q(verification_id__isnull=False),
                name="uniq_x402_verification_operation",
            ),
        ),
    ]
