from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('x402f', '0002_expand_address_fields'),
    ]

    operations = [
        migrations.AlterField(
            model_name='x402authorization',
            name='transaction_hash',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
    ]
