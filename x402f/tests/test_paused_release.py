import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_renderer", ROOT / "deploy/render.py")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


@pytest.mark.parametrize(
    "environ",
    [
        {"FACILITATOR_RELEASE_MODE": "true"},
        {"FACILITATOR_RELEASE_MODE": "restore"},
        {"FACILITATOR_RESTORE_RAILS": "base-exact"},
        {
            "FACILITATOR_RELEASE_MODE": "restore",
            "CONFIRM_FACILITATOR_PAYMENT_RESTORE": "yes",
            "FACILITATOR_RESTORE_RAILS": "all",
        },
        {
            "FACILITATOR_RELEASE_MODE": "restore",
            "CONFIRM_FACILITATOR_PAYMENT_RESTORE": "yes",
            "FACILITATOR_RESTORE_RAILS": "skale-exact",
        },
        {
            "FACILITATOR_RELEASE_MODE": "restore",
            "CONFIRM_FACILITATOR_PAYMENT_RESTORE": "yes",
            "FACILITATOR_RESTORE_RAILS": "solana-recurring",
        },
    ],
)
def test_invalid_restore_configuration_is_rejected(environ):
    with pytest.raises(ValueError):
        renderer.release_configuration(environ)


@pytest.mark.parametrize("tag", ["", "latest", "a" * 129, "bad/tag", "../latest", "test\nvalue"])
def test_invalid_image_tag_is_rejected(tag):
    with pytest.raises(ValueError, match="TAG"):
        renderer.validate_tag(tag)


@pytest.mark.parametrize(
    "missing", ["context", "tag", "deployment.yaml", "service.yaml", "reconciliation-cronjob.yaml"]
)
def test_apply_rejects_incomplete_inputs_before_any_cluster_call(tmp_path, missing):
    shutil.copytree(ROOT / "deploy", tmp_path / "deploy")
    if missing.endswith(".yaml"):
        (tmp_path / "deploy/production" / missing).unlink()
    log = tmp_path / "called"
    fake = tmp_path / "kubectl"
    fake.write_text('#!/bin/sh\n: > "$COMMAND_LOG"\n')
    fake.chmod(0o755)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("FACILITATOR_", "CONFIRM_"))}
    env.update(PATH=f"{tmp_path}:{os.environ['PATH']}", COMMAND_LOG=str(log), TAG="test-1", KUBE_CONTEXT="test-cluster")
    if missing == "context":
        env.pop("KUBE_CONTEXT")
    if missing == "tag":
        env.pop("TAG")
    result = subprocess.run(["sh", str(tmp_path / "deploy/run.sh")], cwd="/", env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not log.exists()


def test_restore_only_receives_requested_signer():
    mode, rails = renderer.release_configuration(
        {
            "FACILITATOR_RELEASE_MODE": "restore",
            "CONFIRM_FACILITATOR_PAYMENT_RESTORE": "yes",
            "FACILITATOR_RESTORE_RAILS": "base-exact",
        }
    )
    for name in ("deployment.yaml", "reconciliation-cronjob.yaml"):
        rendered = renderer.render((ROOT / "deploy/production" / name).read_text(), "test-1", mode, rails)
        assert "name: X402_BASE_EXACT_ENABLED\n" in rendered
        assert "key: BASE_SIGNER_PRIVATE_KEY" in rendered
        assert "name: x402-private" in rendered
        assert "key: SOLANA_SIGNER_PRIVATE_KEY" not in rendered
        assert "SKALE" not in rendered
        assert "key: ARBITRUM_SIGNER_PRIVATE_KEY" not in rendered
        for flag in ("X402_BASE_UPTO_ENABLED", "X402_SOLANA_MAINNET_ENABLED", "X402_ARBITRUM_EXACT_ENABLED"):
            block = rendered.split(f"- name: {flag}", 1)[1].split("- name:", 1)[0]
            assert 'value: "false"' in block
        if name == "reconciliation-cronjob.yaml":
            assert "suspend: true" in rendered


def run_release(tmp_path, *, fail_apply=False, reconcile_pod=False, restore=False):
    if not shutil.which("jq"):
        pytest.skip("jq is required to exercise the release script")
    snapshot = {
        "kind": "Deployment",
        "metadata": {"name": "facilitator-backend"},
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "env": [
                                {"name": "X402_BASE_EXACT_ENABLED", "value": "true"},
                                {
                                    "name": "X402_ARBITRUM_EXACT_ENABLED",
                                    "valueFrom": {"secretKeyRef": {"name": "x402", "key": "ARBITRUM_EXACT_ENABLED"}},
                                },
                                {
                                    "name": "X402_BASE_SIGNER_PRIVATE_KEY",
                                    "valueFrom": {
                                        "secretKeyRef": {"name": "x402-private", "key": "BASE_SIGNER_PRIVATE_KEY"}
                                    },
                                },
                            ]
                        }
                    ]
                }
            },
        },
    }
    cronjob = {
        "kind": "CronJob",
        "metadata": {"name": "facilitator-reconcile"},
        "spec": {"suspend": False, "jobTemplate": {"spec": {"template": snapshot["spec"]["template"]}}},
    }
    (tmp_path / "deployment.json").write_text(json.dumps(snapshot))
    (tmp_path / "cronjob.json").write_text(json.dumps(cronjob))
    fake = tmp_path / "kubectl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        "from pathlib import Path\n"
        "p=Path(os.environ['FAKE_DIR']); a=sys.argv[1:]\n"
        "assert a[:2] == ['--context', 'test-cluster'], a\n"
        "a=a[2:]\n"
        "with (p/'calls.jsonl').open('a') as f: f.write(json.dumps(a)+'\\n')\n"
        "if a[:2]==['get','deployment/facilitator-backend']: print((p/'deployment.json').read_text())\n"
        "elif a[:2]==['get','cronjob/facilitator-reconcile']: print((p/'cronjob.json').read_text())\n"
        "elif a[:2]==['get','pod']:\n"
        " if 'app=facilitator-reconcile' in a and os.environ.get('FAKE_RECONCILE')=='yes':\n"
        "  print('pod/pending-reconcile')\n"
        "elif a[0]=='apply':\n"
        " source=a[a.index('-f')+1]; path=Path(source)\n"
        " if source=='-': data=sys.stdin.read()\n"
        " elif path.is_dir(): data='\\n---\\n'.join(f.read_text() for f in sorted(path.glob('*.yaml')))\n"
        " else: data=path.read_text()\n"
        " with (p/'applied.txt').open('a') as f: f.write(data+'\\n---\\n')\n"
        " if os.environ.get('FAKE_FAIL_APPLY')=='yes':\n"
        "  if path.is_dir() or source.endswith('deployment.yaml'): sys.exit(1)\n"
        "elif a[:2]==['patch','deployment/facilitator-backend']:\n"
        " source=next(x.split('=',1)[1] for x in a if x.startswith('--patch-file='))\n"
        " (p/'rollback.json').write_text(Path(source).read_text())\n"
    )
    fake.chmod(0o755)
    curl = tmp_path / "curl"
    curl.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' \'{"facilitator":{"endpoints":{"verify":"https://facilitator.acedata.cloud/verify"}}}\'\n'
    )
    curl.chmod(0o755)
    environ = {key: value for key, value in os.environ.items() if not key.startswith(("FACILITATOR_", "CONFIRM_"))}
    environ.update(
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        FAKE_DIR=str(tmp_path),
        FAKE_FAIL_APPLY="yes" if fail_apply else "no",
        FAKE_RECONCILE="yes" if reconcile_pod else "no",
        BUILD_NUMBER="test-1",
        KUBE_CONTEXT="test-cluster",
    )
    if restore:
        environ.update(
            FACILITATOR_RELEASE_MODE="restore",
            CONFIRM_FACILITATOR_PAYMENT_RESTORE="yes",
            FACILITATOR_RESTORE_RAILS="base-exact,base-upto,solana-exact",
        )
    result = subprocess.run(["bash", "deploy/release.sh"], cwd=ROOT, env=environ, capture_output=True, text=True)
    calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
    return result, calls


def test_default_release_stages_without_starting_jobs(tmp_path):
    result, calls = run_release(tmp_path)
    assert result.returncode == 0, result.stderr
    applied = (tmp_path / "applied.txt").read_text()
    assert "replicas: 0" in applied
    assert "suspend: true" in applied
    assert "_SIGNER_PRIVATE_KEY" not in applied
    assert not any(call[0] in {"create", "logs", "rollout"} for call in calls)
    assert "kind: Job\n" not in applied
    assert not any(call[:2] == ["delete", "job"] for call in calls)


def test_successful_restore_keeps_reconciliation_suspended(tmp_path):
    result, calls = run_release(tmp_path, restore=True)
    assert result.returncode == 0, result.stderr
    applied = (tmp_path / "applied.txt").read_text()
    assert "replicas: 2" in applied
    assert "key: BASE_SIGNER_PRIVATE_KEY" in applied
    assert "key: SOLANA_SIGNER_PRIVATE_KEY" in applied
    assert "SKALE" not in applied
    assert "key: ARBITRUM_SIGNER_PRIVATE_KEY" not in applied
    assert "suspend: true" in applied
    assert "facilitator-preflight-test-1" in applied
    assert "facilitator-migrate-test-1" in applied
    assert "facilitator-reconcile-smoke" not in applied
    assert not any(call[:2] == ["create", "job"] for call in calls)
    assert not any('"suspend":false' in argument for call in calls for argument in call)


@pytest.mark.parametrize("restore", [False, True])
def test_failed_release_cannot_restore_old_signing_configuration(tmp_path, restore):
    result, calls = run_release(tmp_path, fail_apply=True, restore=restore)
    assert result.returncode != 0
    rollback = json.loads((tmp_path / "rollback.json").read_text())
    assert rollback["spec"]["replicas"] == 0
    env = rollback["spec"]["template"]["spec"]["containers"][0]["env"]
    assert all(not entry["name"].endswith("_SIGNER_PRIVATE_KEY") for entry in env)
    assert all(entry["value"] == "false" and "valueFrom" not in entry for entry in env)
    assert not any(call[:2] == ["create", "job"] for call in calls)


def test_paused_staging_refuses_existing_reconciliation_pods(tmp_path):
    result, calls = run_release(tmp_path, reconcile_pod=True)
    assert result.returncode != 0
    assert "Stop existing reconciliation Jobs" in result.stderr
    assert not any(call[0] == "create" for call in calls)
    assert "rollback.json" in {path.name for path in tmp_path.iterdir()}
