from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("x402f", "0008_add_verification_id")]

    operations = [
        migrations.AlterField(
            model_name="x402authorization",
            name="status",
            field=models.CharField(
                choices=[
                    ("verified", "Verified"),
                    ("settling", "Settling"),
                    ("settled", "Settled"),
                    ("released", "Released"),
                    ("failed", "Failed"),
                ],
                default="verified",
                max_length=16,
            ),
        )
    ]
