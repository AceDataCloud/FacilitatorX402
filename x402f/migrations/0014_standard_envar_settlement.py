from django.db import migrations, models


def quarantine_legacy(apps, schema_editor):
    binding = apps.get_model("x402f", "EnvarDelegationAuthorization")
    authorization = apps.get_model("x402f", "X402Authorization")
    database = schema_editor.connection.alias
    for row in binding.objects.using(database).all().iterator():
        authorization.objects.using(database).filter(pk=row.authorization_id).update(
            verification_id=f"envar:legacy:{row.registration_id}"
        )


class Migration(migrations.Migration):
    dependencies = [("x402f", "0013_envardelegationauthorization")]

    operations = [
        migrations.RunPython(quarantine_legacy),
        # Preserve historical IDs and tables without active ORM models or foreign-key effects.
        migrations.AlterField(
            model_name="envardelegationauthorization",
            name="authorization",
            field=models.BigIntegerField(db_column="authorization_id", unique=True),
        ),
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.DeleteModel(name="EnvarDelegationAuthorization"),
                migrations.DeleteModel(name="EnvarDelegationRegistration"),
            ]
        ),
        migrations.AddConstraint(
            model_name="x402authorization",
            constraint=models.UniqueConstraint(
                fields=["verification_id"],
                condition=models.Q(verification_id__startswith="envar:"),
                name="x402_envar_intent_unique",
            ),
        ),
    ]
