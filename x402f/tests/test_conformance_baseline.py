import json
from pathlib import Path

import pytest

from conformance.run_baseline import (
    baseline_timeout_seconds,
    redact_diagnostics,
    validate_baseline,
    validate_output_path,
    validate_provider_contract,
)

ROOT = Path(__file__).resolve().parents[2]


def test_provider_uses_raw_mode_without_protocol_transformations():
    provider = (ROOT / "conformance/providers/acedata-self-hosted.yml").read_text()
    assert "mode: raw" in provider
    assert "  - core-v2" in provider
    assert "network_map" not in provider
    assert "request_transform" not in provider
    assert "response_transform" not in provider


def test_baseline_policy_is_immutable_and_expected_red():
    expected = json.loads((ROOT / "conformance/baseline_expected.json").read_text())
    assert expected["expected"] == "RED"
    assert expected["allow_expected_rewrite"] is False
    assert expected["minimum_failed"] >= 1


def test_baseline_rejects_non_protocol_statuses():
    expected = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": "acedata-self-hosted",
        "profile": "core-v2",
        "required_case_count": 1,
        "minimum_failed": 1,
        "expected_failed_case_ids": ["CORE-001"],
    }
    with pytest.raises(ValueError, match="non-protocol"):
        validate_baseline(
            {
                "suite_version": "2026-07-19.1",
                "manifest_version": "2026-07-19.1",
                "provider": {"id": "acedata-self-hosted"},
                "results": [{"id": "CORE-001", "profile": "core-v2", "status": "INFRA_ERROR"}],
            },
            expected,
            {"CORE-001"},
        )


def test_provider_contract_requires_raw_authenticated_core_profile():
    provider = (ROOT / "conformance/providers/acedata-self-hosted.yml").read_text()
    validate_provider_contract(provider)
    with pytest.raises(ValueError, match="provider config"):
        validate_provider_contract(provider.replace("X-Settlement-Token", "Wrong-Header"))
    with pytest.raises(ValueError, match="provider config"):
        validate_provider_contract(provider + "\nrequest_transform:\n  rename: network\n")
    with pytest.raises(ValueError, match="strict YAML"):
        validate_provider_contract(provider + "\nmode: adapter\n")


def test_timeout_covers_each_manifest_case_and_margin():
    assert baseline_timeout_seconds({"timeout_seconds": 30}, 53) == 1620


def test_diagnostics_redact_secret_and_settlement_header():
    secret = "top-secret-settlement-token"
    redacted = redact_diagnostics(
        f"token={secret} X-Settlement-Token: leaked-value 'X-Settlement-Token': 'quoted-value'",
        secret,
    )
    assert secret not in redacted
    assert "leaked-value" not in redacted
    assert "quoted-value" not in redacted


def test_output_path_rejects_arbitrary_directories(tmp_path: Path):
    with pytest.raises(ValueError, match="dedicated baseline directory"):
        validate_output_path(tmp_path)


def test_baseline_accepts_protocol_failures():
    expected = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": "acedata-self-hosted",
        "profile": "core-v2",
        "required_case_count": 1,
        "minimum_failed": 1,
        "expected_failed_case_ids": ["CORE-001"],
    }
    validate_baseline(
        {
            "suite_version": "2026-07-19.1",
            "manifest_version": "2026-07-19.1",
            "provider": {"id": "acedata-self-hosted"},
            "results": [{"id": "CORE-001", "profile": "core-v2", "status": "FAIL"}],
        },
        expected,
        {"CORE-001"},
    )


def test_baseline_rejects_partial_or_wrong_profile_report():
    expected = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": "acedata-self-hosted",
        "profile": "core-v2",
        "required_case_count": 2,
        "minimum_failed": 1,
        "expected_failed_case_ids": ["CORE-001"],
    }
    report = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": {"id": "acedata-self-hosted"},
        "results": [{"id": "CORE-001", "profile": "other", "status": "FAIL"}],
    }
    with pytest.raises(ValueError):
        validate_baseline(report, expected, {"CORE-001", "CORE-002"})


def test_baseline_rejects_duplicate_or_missing_manifest_case_ids():
    expected = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": "acedata-self-hosted",
        "profile": "core-v2",
        "required_case_count": 2,
        "minimum_failed": 1,
        "expected_failed_case_ids": ["CORE-001"],
    }
    report = {
        "suite_version": "2026-07-19.1",
        "manifest_version": "2026-07-19.1",
        "provider": {"id": "acedata-self-hosted"},
        "results": [
            {"id": "CORE-001", "profile": "core-v2", "status": "FAIL"},
            {"id": "CORE-001", "profile": "core-v2", "status": "FAIL"},
        ],
    }
    with pytest.raises(ValueError, match="case IDs"):
        validate_baseline(report, expected, {"CORE-001", "CORE-002"})
