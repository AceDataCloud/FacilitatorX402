from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("x402f", "0010_bazaar_catalog_snapshot")]

    operations = [migrations.DeleteModel(name="BazaarCatalogSnapshot")]
