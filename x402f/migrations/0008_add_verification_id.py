from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("x402f", "0007_add_prepared_transaction")]

    operations = [
        migrations.AddField(
            model_name="x402authorization",
            name="verification_id",
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
    ]
