from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("x402f", "0005_add_settling_status")]

    operations = [
        migrations.AlterField(
            model_name="x402authorization",
            name="signature",
            field=models.TextField(),
        ),
    ]
