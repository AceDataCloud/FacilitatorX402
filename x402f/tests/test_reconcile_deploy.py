import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_reconciliation_budget_and_cleanup():
    manifest = (ROOT / "deploy/production/reconciliation-cronjob.yaml").read_text()
    release = (ROOT / "deploy/release.sh").read_text()
    tx_timeout = int(re.search(r"X402_TX_TIMEOUT_SECONDS\n\s+value: \"(\d+)\"", manifest).group(1))
    lease = int(re.search(r"X402_SETTLEMENT_LEASE_SECONDS\n\s+value: \"(\d+)\"", manifest).group(1))
    deadline = int(re.search(r"activeDeadlineSeconds: (\d+)", manifest).group(1))
    runtime = int(re.search(r'"--max-runtime-seconds", "(\d+)"', manifest).group(1))
    assert tx_timeout < runtime < deadline < lease
    assert "ttlSecondsAfterFinished: 600" in manifest
    assert "concurrencyPolicy: Forbid" in manifest
    assert f"--timeout={deadline + 60}s" in release
