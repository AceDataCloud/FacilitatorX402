from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("x402f", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="x402authorization",
            name="payer",
            field=models.CharField(max_length=128),
        ),
        migrations.AlterField(
            model_name="x402authorization",
            name="pay_to",
            field=models.CharField(max_length=128),
        ),
    ]
