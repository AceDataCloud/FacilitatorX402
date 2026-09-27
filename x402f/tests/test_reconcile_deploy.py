from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_reconciliation_budget_and_cleanup():
    manifest = yaml.safe_load((ROOT / "deploy/production/reconciliation-cronjob.yaml").read_text())
    job = manifest["spec"]["jobTemplate"]["spec"]
    env = {item["name"]: item.get("value") for item in job["template"]["spec"]["containers"][0]["env"]}
    tx_timeout = int(env["X402_TX_TIMEOUT_SECONDS"])
    lease = int(env["X402_SETTLEMENT_LEASE_SECONDS"])
    deadline = job["activeDeadlineSeconds"]
    runtime = 240
    command = job["template"]["spec"]["containers"][0]["command"]
    assert command[command.index("--max-runtime-seconds") + 1] == str(runtime)
    assert tx_timeout < runtime < deadline < lease
    assert job["ttlSecondsAfterFinished"] == 600
    assert manifest["spec"]["concurrencyPolicy"] == "Forbid"
    assert f"--timeout={deadline + 60}s" in (ROOT / "deploy/release.sh").read_text()
