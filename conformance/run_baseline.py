from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


class StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, f"duplicate key: {key}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def validate_baseline(report: dict, expected: dict, manifest_case_ids: set[str]) -> None:
    if report.get("suite_version") != expected["suite_version"]:
        raise ValueError("baseline report suite version mismatch")
    if report.get("manifest_version") != expected["manifest_version"]:
        raise ValueError("baseline report manifest version mismatch")
    if report.get("provider", {}).get("id") != expected["provider"]:
        raise ValueError("baseline report provider mismatch")
    results = report.get("results") or []
    if len(results) != int(expected["required_case_count"]):
        raise ValueError("baseline report does not cover the full manifest")
    result_case_ids = {str(result.get("id")) for result in results}
    if len(result_case_ids) != len(results) or result_case_ids != manifest_case_ids:
        raise ValueError("baseline report case IDs do not match the manifest")
    if {result.get("profile") for result in results} != {expected["profile"]}:
        raise ValueError("baseline report profile mismatch")
    statuses = {result.get("status") for result in results}
    if not statuses <= {"PASS", "FAIL"}:
        raise ValueError("baseline report contains non-protocol result statuses")
    failed_case_ids = {str(result["id"]) for result in results if result.get("status") == "FAIL"}
    expected_failed_case_ids = {str(case_id) for case_id in expected["expected_failed_case_ids"]}
    if failed_case_ids != expected_failed_case_ids:
        raise ValueError("baseline failed case IDs changed; investigate suite/provider drift")


def load_provider_contract(provider_text: str) -> dict[str, Any]:
    try:
        provider = yaml.load(provider_text, Loader=StrictSafeLoader)
    except yaml.YAMLError as exc:
        raise ValueError("provider config is not valid strict YAML") from exc
    if not isinstance(provider, dict):
        raise ValueError("provider config must be a mapping")
    return provider


def validate_provider_contract(provider_text: str) -> dict[str, Any]:
    provider = load_provider_contract(provider_text)
    auth = provider.get("auth")
    forbidden = {"network_map", "request_transform", "response_transform"} & provider.keys()
    if (
        provider.get("id") != "acedata-self-hosted"
        or provider.get("mode") != "raw"
        or provider.get("profiles") != ["core-v2"]
        or not isinstance(auth, dict)
        or auth.get("type") != "header"
        or auth.get("header") != "X-Settlement-Token"
        or auth.get("secret_env") != "FACILITATOR_SETTLE_TOKEN"
        or forbidden
    ):
        raise ValueError("provider config does not match the raw Ace baseline contract")
    return provider


def baseline_timeout_seconds(provider: dict[str, Any], case_count: int) -> int:
    try:
        provider_timeout = int(provider["timeout_seconds"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("provider timeout_seconds must be a positive integer") from exc
    if provider_timeout <= 0 or case_count <= 0:
        raise ValueError("provider timeout and case count must be positive")
    return case_count * provider_timeout + 30


def redact_diagnostics(value: str, secret: str) -> str:
    redacted = value.replace(secret, "[REDACTED]") if secret else value
    return re.sub(
        r"(?i)(X-Settlement-Token(?:['\"]?\s*[:=]\s*['\"]?))[^\s,'\"}]+",
        r"\1[REDACTED]",
        redacted,
    )


def validate_output_path(output: Path) -> None:
    expected_output_root = (Path(__file__).resolve().parent / "reports").resolve()
    if output.resolve() != expected_output_root:
        raise ValueError(f"output must be the dedicated baseline directory: {expected_output_root}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--conformance-root", type=Path, required=True)
    parser.add_argument("--provider", type=Path, default=Path("conformance/providers/acedata-self-hosted.yml"))
    parser.add_argument("--expected", type=Path, default=Path("conformance/baseline_expected.json"))
    parser.add_argument("--output", type=Path, default=Path("conformance/reports"))
    args = parser.parse_args()

    conformance_root = args.conformance_root.resolve()
    expected = json.loads(args.expected.resolve().read_text())
    settlement_secret = os.environ.get("FACILITATOR_SETTLE_TOKEN", "")
    if not settlement_secret:
        raise RuntimeError("FACILITATOR_SETTLE_TOKEN is required for a protocol baseline")

    provider = args.provider.resolve()
    output = args.output.resolve()
    validate_output_path(output)
    output.mkdir(parents=True, exist_ok=True)
    provider_text = provider.read_text()
    provider_config = validate_provider_contract(provider_text)
    report_path = output / "acedata-self-hosted.json"
    stdout_path = output / "runner.stdout.log"
    stderr_path = output / "runner.stderr.log"
    for stale_path in (report_path, stdout_path, stderr_path):
        stale_path.unlink(missing_ok=True)
    manifest = conformance_root / "profiles/core-v2/2026-07-19/manifest.json"
    if not manifest.is_file():
        raise RuntimeError(f"conformance manifest not found: {manifest}")
    manifest_case_ids = {str(case["id"]) for case in json.loads(manifest.read_text())["cases"]}
    runner_timeout = baseline_timeout_seconds(provider_config, len(manifest_case_ids))
    command = [
        sys.executable,
        "-m",
        "x402_conformance",
        "--provider",
        str(provider),
        "--manifest",
        str(manifest),
        "--output",
        str(output),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=conformance_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=runner_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
        stdout_path.write_text(redact_diagnostics(stdout, settlement_secret))
        stderr_path.write_text(redact_diagnostics(stderr or "conformance runner timed out", settlement_secret))
        return 124
    if not report_path.exists() or completed.returncode not in {0, 1}:
        stdout_path.write_text(redact_diagnostics(completed.stdout, settlement_secret))
        stderr_path.write_text(redact_diagnostics(completed.stderr, settlement_secret))
        print(redact_diagnostics(completed.stderr, settlement_secret), file=sys.stderr)
        return completed.returncode or 2
    try:
        validate_baseline(json.loads(report_path.read_text()), expected, manifest_case_ids)
    except (KeyError, TypeError, ValueError):
        stdout_path.write_text(redact_diagnostics(completed.stdout, settlement_secret))
        stderr_path.write_text(redact_diagnostics(completed.stderr, settlement_secret))
        print(redact_diagnostics(completed.stdout, settlement_secret), file=sys.stderr)
        print(redact_diagnostics(completed.stderr, settlement_secret), file=sys.stderr)
        raise
    print(f"baseline_report={report_path} expected=RED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
