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


def test_deploy_keeps_the_hardened_us_workflow() -> None:
    text = workflow_text()

    release = (ROOT / "deploy/release.sh").read_text()
    run = (ROOT / "deploy/run.sh").read_text()

    assert "kubeconfig: ${{ secrets.KUBE_CONFIG_SV }}" in text
    assert "run: bash ./deploy/release.sh" in text
    assert 'TAG="$TAG" sh deploy/run.sh' in release
    assert "facilitator-bazaar-refresh" not in run
    assert "kubectl delete cronjob/facilitator-bazaar-refresh" in release
    assert ".metadata.ownerReferences[]?" in release
    assert "CronJob" in release
    assert "--cascade=foreground" in release
    assert "--timeout=120s --wait=true" in release
    assert "https://facilitator.acedata.cloud/.well-known/x402" in release
    assert release.count("--connect-timeout 5 --max-time 15") >= 2
    assert 'status" = "410"' in release
    assert "resource_discovery_retired" in release
    cleanup = release.split("kubectl patch cronjob/facilitator-bazaar-refresh", 1)[1]
    assert cleanup.index("kubectl delete cronjob/facilitator-bazaar-refresh") < cleanup.index("BAZAAR_JOBS=")
    rollback_body = release.split("rollback() {", 1)[1].split("on_exit() {", 1)[0]
    assert rollback_body.index('kubectl apply -f "$ORIGINAL_BAZAAR_CRONJOB_FILE"') < rollback_body.index(
        "kubectl patch deployment/facilitator-backend"
    )
    rollback = (ROOT / "deploy/rollback-bazaar-retirement.sh").read_text()
    assert "OLD_TAG is required" in rollback
    assert "CATALOG_ACCESS_TOKEN is required" in rollback
    assert "CATALOG_SIGNING_SECRET is required" in rollback
    assert "CURRENT_DEPLOYMENT" in rollback
    assert "CURRENT_SECRET" in rollback
    assert "restore_current" in rollback
    assert 'kubectl apply -f "$CURRENT_SECRET"' not in rollback
    assert 'original="$(jq -r' in rollback
    assert "--type=json" in rollback
    assert 'op: "remove"' in rollback
    assert "base64 | tr -d" in rollback
    assert "restore_failed=0" in rollback
    assert "|| restore_failed=1" in rollback
    assert 'return "$restore_failed"' in rollback
    assert "trap on_exit EXIT" in rollback
    assert "python manage.py check" in rollback
    assert "deploy/rollback/bazaar-cronjob.yaml" in rollback
    assert "suspend: true" in (ROOT / "deploy/rollback/bazaar-cronjob.yaml").read_text()
    preflight = rollback.index("python manage.py check")
    serving_cutover = rollback.index("deploy/rollback/deployment.yaml")
    refresh = rollback.index('kubectl create job "$SMOKE_JOB"')
    assert preflight < serving_cutover < refresh
    assert refresh < rollback.index('"suspend":false')
    assert "kubectl wait" not in run
    assert "docker compose build" in text
    assert "docker compose push" in text


def test_runtime_changes_are_not_ignored() -> None:
    text = workflow_text()
    ignored_block = text.split("paths-ignore:", 1)[1].split("workflow_dispatch:", 1)[0]

    for runtime_path in ("x402f/**", "poetry.lock", "Dockerfile", "deploy/**", ".github/workflows/**"):
        assert runtime_path not in ignored_block
