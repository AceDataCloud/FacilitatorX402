from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "deploy.yaml"
DEPLOYMENT = ROOT / "deploy" / "production" / "deployment.yaml"


def workflow_text() -> str:
    return WORKFLOW.read_text()


def test_settlement_deployment_keeps_pay_to_in_secrets() -> None:
    deployment = DEPLOYMENT.read_text()

    for name in ("X402_BASE_PAY_TO", "X402_SOLANA_PAY_TO", "X402_SKALE_PAY_TO"):
        block = deployment.split(f"- name: {name}", 1)[1].split("- name:", 1)[0]
        assert "secretKeyRef" in block
        assert "value: " not in block


def test_deploy_runs_on_main_push_and_manual_dispatch() -> None:
    text = workflow_text()

    assert "  push:\n" in text
    assert "    branches:\n      - main\n" in text
    assert "  workflow_dispatch:\n" in text
    assert "if: github.ref == 'refs/heads/main'" in text


def test_production_deploys_queue_instead_of_cancelling() -> None:
    text = workflow_text()

    assert "concurrency:\n  group: facilitator-production\n  cancel-in-progress: false\n" in text
    assert "cancel-in-progress: true" not in text


def test_deploy_targets_the_hong_kong_financial_publisher() -> None:
    text = workflow_text()
    release = (ROOT / "deploy/release.sh").read_text()
    run = (ROOT / "deploy/run.sh").read_text()

    assert "kubeconfig: ${{ secrets.KUBE_CONFIG_HK }}" in text
    assert "run: bash ./deploy/release.sh" in text
    assert 'TAG="$TAG" sh deploy/run.sh' in release
    assert "facilitator-bazaar-refresh" not in release
    assert "facilitator-bazaar-refresh" not in run
    assert "kubectl wait" not in run
    assert "docker compose build" in text
    assert "docker compose push" in text


def test_runtime_changes_are_not_ignored() -> None:
    text = workflow_text()
    ignored_block = text.split("paths-ignore:", 1)[1].split("workflow_dispatch:", 1)[0]

    for runtime_path in ("x402f/**", "poetry.lock", "Dockerfile", "deploy/**", ".github/workflows/**"):
        assert runtime_path not in ignored_block


def test_solana_recurring_is_enabled_in_runtime_and_reconciler() -> None:
    cronjob = (ROOT / "deploy" / "production" / "reconciliation-cronjob.yaml").read_text()
    for manifest in (DEPLOYMENT.read_text(), cronjob):
        block = manifest.split("- name: X402_SOLANA_RECURRING_ENABLED", 1)[1].split("- name:", 1)[0]
        assert 'value: "true"' in block
        assert 'value: "false"' not in block


def test_signing_fields_use_only_the_private_signer_secret():
    for path in (DEPLOYMENT, ROOT / "deploy/production/reconciliation-cronjob.yaml"):
        source = path.read_text()
        for network in ("BASE", "SOLANA", "SKALE", "ARBITRUM"):
            block = source.split(f"- name: X402_{network}_SIGNER_PRIVATE_KEY", 1)[1].split("- name:", 1)[0]
            assert "name: x402-signer-private" in block
            assert "name: x402\n" not in block


def test_paused_release_exits_before_any_write(tmp_path):
    import json
    import os
    import shutil
    import subprocess

    if not shutil.which("jq"):
        import pytest

        pytest.skip("jq required for release shell test")
    fixture = tmp_path / "kubectl"
    log = tmp_path / "calls"
    fixture.write_text(
        "#!/usr/bin/env python3\n"
        + """import json,os,sys
with open(os.environ["PROBE_LOG"],"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")
args=sys.argv[1:]
if args[:2]==["get","deployment/facilitator-backend"]:
 print(json.dumps({"spec":{"replicas":0}}))
elif args[:2]==["get","cronjob/facilitator-reconcile"]:
 print(json.dumps({"spec":{"suspend":True}}))
elif args[:2]==["delete","job"]:
 pass
else:
 raise SystemExit(44)
"""
    )
    fixture.chmod(0o755)
    result = subprocess.run(
        ["bash", "deploy/release.sh"],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "PROBE_LOG": str(log),
            "BUILD_NUMBER": "probe",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Facilitator remains paused" in result.stdout
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(call[0] in ["get", "delete"] for call in calls)
    assert not any(call[0] in ["apply", "scale", "patch", "create"] for call in calls)


def test_hong_kong_publisher_checks_only_existing_named_resources():
    text = workflow_text()
    assert "kubectl get deployment/facilitator-backend -n acedatacloud" in text
    assert "kubectl get service/facilitator-backend -n acedatacloud" in text
    assert "kubectl get nodes" not in text
    assert "kubectl get svc -n acedatacloud" not in text
