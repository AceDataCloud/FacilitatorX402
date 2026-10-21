"""Two real Django services over loopback HTTP; the chain is explicitly synthetic."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

FACILITATOR_SERVER = r"""
import django, json, sys
from pathlib import Path
django.setup()
from django.core.management import call_command
call_command("migrate", verbosity=0)
from django.core.wsgi import get_wsgi_application
from django.test import override_settings
from unittest.mock import patch
from types import SimpleNamespace
from wsgiref.simple_server import make_server, WSGIRequestHandler
from x402f.tests.test_envar_standard import SyntheticChain, ENVAR_SETTINGS
from x402f.official import build_facilitator
from x402f.models import X402Authorization
chain = SyntheticChain()
chain.proven = False
paths = []
def configured(network, on_transaction_prepared=None, on_transaction_broadcast=None):
    if on_transaction_prepared is not None:
        chain.on_prepared = on_transaction_prepared
    return SimpleNamespace(facilitator=build_facilitator(chain), signer_for=lambda _: chain)
app = get_wsgi_application()
def handle(environ, start_response):
    path = environ["PATH_INFO"]
    if path == "/__test/prove":
        chain.proven = True
    if path.startswith("/__test/"):
        data = json.dumps({"paths": paths, "broadcasts": chain.events.count("broadcast"),
            "records": X402Authorization.objects.count()}).encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [data]
    paths.append(path)
    return app(environ, start_response)
class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass
with override_settings(**ENVAR_SETTINGS), patch("x402f.views_official._configured", side_effect=configured):
    server = make_server("127.0.0.1", 0, handle, handler_class=Quiet)
    Path(sys.argv[1]).write_text(str(server.server_port))
    server.serve_forever()
"""

ENVAR_CLIENT = r"""
import django, json, sys, time
django.setup()
from django.core.management import call_command
call_command("migrate", verbosity=0)
from django.test import override_settings
from eth_account import Account
from eth_account.messages import encode_typed_data
from x402.mechanisms.evm.types import AUTHORIZATION_TYPES
from apps.a2a.models import DelegationPaymentIntent
from apps.a2a.settlement import authorization_nonce, requirements
from apps.runtime.models import Run, RunStatus
from tests.test_delegation_registration import waiting_run
from tests.test_delegation_settlement import bind_wallet
from tests.test_agent_connections import post_json
import httpx
base = sys.argv[1]
with override_settings(ENVAR_DELEGATION_PAYMENT_ENABLED=True, ENVAR_DELEGATION_FACILITATOR_URL=base,
                       ENVAR_DELEGATION_FACILITATOR_TOKEN="envar-secret"):
    client, csrf, run, intent = waiting_run()
    assert Run.objects.get(pk=run.id).status == RunStatus.WAITING_PAYMENT
    assert not Run.objects.filter(parent_run=run).exists()
    payer = Account.create()
    bind_wallet(client, csrf, run, payer=payer.address)
    auth = {"from": payer.address, "to": intent.recipient, "value": intent.amount_atomic,
        "validAfter": "0", "validBefore": str(int(time.time()) + 600), "nonce": authorization_nonce(intent)}
    typed = {**auth, "value": int(auth["value"]), "validAfter": 0,
        "validBefore": int(auth["validBefore"]), "nonce": bytes.fromhex(auth["nonce"][2:])}
    signature = payer.sign_message(encode_typed_data(
        domain_data={"name":"USD Coin","version":"2","chainId":8453,"verifyingContract":intent.asset},
        message_types=AUTHORIZATION_TYPES, message_data=typed)).signature.to_0x_hex()
    payment = {"x402Version":2,"accepted":requirements(intent),
        "payload":{"authorization":auth,"signature":signature}}
    url = f"/api/v1/runs/{run.id}/delegation-payment"
    pending = post_json(client, url+"/settle", {"payment":payment}, csrf)
    assert pending.status_code == 200 and pending.json()["state"] == "settlement_pending", pending.content
    assert Run.objects.get(pk=run.id).status == RunStatus.WAITING_PAYMENT
    assert not Run.objects.filter(parent_run=run).exists()
    assert post_json(client, url+"/resume", {}, csrf).status_code == 400
    assert post_json(client, url+"/settle", {"payment":payment}, csrf).status_code == 400
    assert post_json(client, url+"/reconcile", {}, csrf).json()["state"] == "settlement_pending"
    intent.refresh_from_db()
    original_digest = intent.payment_payload_digest
    with httpx.Client(trust_env=False) as http:
        http.get(base+"/__test/prove").raise_for_status()
        settled = post_json(client, url+"/reconcile", {}, csrf)
        assert settled.json()["state"] == "settled", settled.content
        assert Run.objects.get(pk=run.id).status == RunStatus.QUEUED
        intent.refresh_from_db()
        assert intent.payment_payload_digest == original_digest
        assert not Run.objects.filter(parent_run=run).exists()
        stats = http.get(base+"/__test/stats").json()
    assert stats == {"paths":["/settle","/settle","/settle"],"broadcasts":1,"records":1}, stats
    assert run.work_attempts.count() == 1
    print(json.dumps({"synthetic_chain":True,"real_payment":False,"envar_state":"settled",
        "parent_status":"queued","child_started_before_confirmation":False,**stats}))
"""


def test_merged_envar_calls_standard_settle_and_waits_for_exact_receipt(tmp_path):
    source = os.environ.get("ENVAR_SOURCE_DIR")
    if not source:
        pytest.skip("Set ENVAR_SOURCE_DIR to run the two-repository loopback integration")
    server_root = Path(source).resolve() / "server"
    assert (server_root / "manage.py").is_file()
    ready = tmp_path / "ready"
    env = {
        **os.environ,
        "TENCENT_SSM_SECRET_NAME": "",
        "DJANGO_SETTINGS_MODULE": "core.settings",
        "DATABASE_ENGINE": "django.db.backends.sqlite3",
        "PGSQL_DATABASE_FACILITATOR": str(tmp_path / "fac.db"),
    }
    with (tmp_path / "facilitator.log").open("w+") as log:
        process = subprocess.Popen(
            [sys.executable, "-c", FACILITATOR_SERVER, str(ready)],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            stdout=log,
            stderr=log,
        )
        try:
            for _ in range(200):
                if ready.exists():
                    break
                if process.poll() is not None:
                    log.seek(0)
                    pytest.fail(log.read())
                time.sleep(0.05)
            assert ready.exists(), "Loopback server did not start"
            result = subprocess.run(
                [sys.executable, "-c", ENVAR_CLIENT, f"http://127.0.0.1:{ready.read_text()}"],
                cwd=server_root,
                env={
                    **env,
                    "DJANGO_SETTINGS_MODULE": "config.settings_test",
                    "DATABASE_URL": f"sqlite:///{tmp_path / 'envar.db'}",
                    "ALLOWED_HOSTS": "testserver,127.0.0.1",
                },
                capture_output=True,
                text=True,
                timeout=45,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            evidence = json.loads(result.stdout.strip().splitlines()[-1])
            assert evidence["real_payment"] is False and evidence["broadcasts"] == 1
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
