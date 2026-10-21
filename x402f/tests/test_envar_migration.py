import os
import subprocess
import sys
from pathlib import Path


def test_forward_migration_preserves_legacy_audit_rows_and_quarantines_authorizations(tmp_path):
    script = """
import uuid
import django
django.setup()
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone
executor = MigrationExecutor(connection)
old = [("x402f", "0013_envardelegationauthorization")]
executor.migrate(old)
apps = executor.loader.project_state(old).apps
Authorization = apps.get_model("x402f", "X402Authorization")
Registration = apps.get_model("x402f", "EnvarDelegationRegistration")
Binding = apps.get_model("x402f", "EnvarDelegationAuthorization")
intent = uuid.uuid4()
registration = Registration.objects.create(intent_id=intent, parent_run_id=uuid.uuid4(), attempt_id=uuid.uuid4(),
    request_owner_account_id="buyer", agent_id=uuid.uuid4(), owner_account_id="seller", agent_version_id=uuid.uuid4(),
    payee_revision=1, recipient="0x"+"1"*40, network="eip155:8453", asset="0x"+"2"*40, amount_atomic="10000",
    terms_digest="a"*64, expires_at=timezone.now())
authorization = Authorization.objects.create(nonce="archived-nonce", verification_id=str(intent), payer="buyer",
    pay_to="seller", value="10000", valid_after=timezone.now(), valid_before=timezone.now(), signature="audit",
    payment_requirements={}, payment_payload={})
Binding.objects.create(registration=registration, authorization=authorization)
executor = MigrationExecutor(connection)
executor.migrate(executor.loader.graph.leaf_nodes())
from x402f.models import X402Authorization
assert X402Authorization.objects.get().verification_id == f"envar:legacy:{intent}"
with connection.cursor() as cursor:
    cursor.execute("SELECT authorization_id FROM x402f_envardelegationauthorization")
    assert cursor.fetchone()[0] == authorization.pk
    cursor.execute("SELECT recipient FROM x402f_envardelegationregistration")
    assert cursor.fetchone()[0] == "0x"+"1"*40
    constraints = connection.introspection.get_constraints(cursor, "x402f_envardelegationauthorization")
    assert not any(c.get("foreign_key", (None,))[0] == "x402f_x402authorization"
                   for c in constraints.values() if c.get("foreign_key"))
from django.apps import apps
assert not any(m.__name__.startswith("EnvarDelegation") for m in apps.get_models())
print("historical rows and IDs preserved; legacy authorization quarantined")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[2],
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "core.settings",
            "TENCENT_SSM_SECRET_NAME": "",
            "DATABASE_ENGINE": "django.db.backends.sqlite3",
            "PGSQL_DATABASE_FACILITATOR": str(tmp_path / "audit.db"),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "historical rows and IDs preserved" in result.stdout
