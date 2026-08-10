from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("x402f", "0009_add_released_status")]

    operations = [
        migrations.CreateModel(
            name="BazaarCatalogSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("snapshot", models.CharField(max_length=64, unique=True)),
                ("version", models.CharField(max_length=32)),
                ("manifest_sha256", models.CharField(max_length=64)),
                ("source_signature", models.TextField()),
                ("source_payload", models.JSONField()),
                ("projected_payload", models.JSONField()),
                ("resource_count", models.PositiveIntegerField(default=0)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("candidate", "Candidate"),
                            ("active", "Active"),
                            ("rejected", "Rejected"),
                            ("superseded", "Superseded"),
                        ],
                        default="candidate",
                        max_length=16,
                    ),
                ),
                ("fetched_at", models.DateTimeField()),
                ("probed_at", models.DateTimeField(blank=True, null=True)),
                ("activated_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField()),
                ("error_summary", models.CharField(blank=True, max_length=500)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddConstraint(
            model_name="bazaarcatalogsnapshot",
            constraint=models.UniqueConstraint(
                condition=models.Q(status="active"),
                fields=("status",),
                name="uniq_active_bazaar_catalog_snapshot",
            ),
        ),
    ]
