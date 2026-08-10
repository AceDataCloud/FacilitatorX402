from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "deploy.yaml"
DEPLOYMENT = ROOT / "deploy" / "production" / "deployment.yaml"


def workflow_text() -> str:
    return WORKFLOW.read_text()


def test_public_merchant_pay_to_addresses_are_versioned() -> None:
    deployment = DEPLOYMENT.read_text()

    assert deployment.count('value: "0x4F0E2D3477a1B94CF33d16E442CEe4733dadCeE7"') == 2
    assert deployment.count('value: "5iVXFrYaYWX2GUTbkQj8mDBoBhAX8bneYigS2LJTia43"') == 1
    for name in ("X402_BASE_PAY_TO", "X402_SOLANA_PAY_TO", "X402_SKALE_PAY_TO"):
        block = deployment.split(f"- name: {name}", 1)[1].split("- name:", 1)[0]
        assert "secretKeyRef" not in block


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

    assert "kubeconfig: ${{ secrets.KUBE_CONFIG_SV }}" in text
    assert "run: bash ./deploy/run.sh" in text
    assert "docker compose build" in text
    assert "docker compose push" in text


def test_runtime_changes_are_not_ignored() -> None:
    text = workflow_text()
    ignored_block = text.split("paths-ignore:", 1)[1].split("workflow_dispatch:", 1)[0]

    for runtime_path in ("x402f/**", "poetry.lock", "Dockerfile", "deploy/**", ".github/workflows/**"):
        assert runtime_path not in ignored_block
