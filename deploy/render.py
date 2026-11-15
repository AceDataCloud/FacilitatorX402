#!/usr/bin/env python3
"""Render paused templates; payment restoration requires an explicit rail list."""

import argparse
import os
import re
import sys
from pathlib import Path

RAIL_FLAGS = {
    "base-exact": "X402_BASE_EXACT_ENABLED",
    "base-upto": "X402_BASE_UPTO_ENABLED",
    "solana-exact": "X402_SOLANA_MAINNET_ENABLED",
    "solana-recurring": "X402_SOLANA_RECURRING_ENABLED",
    "skale-exact": "X402_SKALE_EXACT_ENABLED",
    "arbitrum-exact": "X402_ARBITRUM_EXACT_ENABLED",
}
RAIL_SIGNERS = {
    "base-exact": "BASE",
    "base-upto": "BASE",
    "solana-exact": "SOLANA",
    "solana-recurring": "SOLANA",
    "skale-exact": "SKALE",
    "arbitrum-exact": "ARBITRUM",
}


def release_configuration(environ):
    mode = environ.get("FACILITATOR_RELEASE_MODE", "paused")
    if mode not in {"paused", "restore"}:
        raise ValueError("FACILITATOR_RELEASE_MODE must be paused or restore")
    rails = set(filter(None, environ.get("FACILITATOR_RESTORE_RAILS", "").split(",")))
    if mode == "paused":
        if rails:
            raise ValueError("A paused release cannot request payment rails")
        return mode, rails
    if environ.get("CONFIRM_FACILITATOR_PAYMENT_RESTORE") != "yes":
        raise ValueError("Restoring payment requires CONFIRM_FACILITATOR_PAYMENT_RESTORE=yes")
    if not rails or rails - RAIL_FLAGS.keys():
        raise ValueError("Restoring payment requires an exact supported rail allowlist")
    if "solana-recurring" in rails and "solana-exact" not in rails:
        raise ValueError("solana-recurring requires solana-exact")
    return mode, rails


def validate_tag(tag):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", tag):
        raise ValueError("TAG is not a valid image tag")


def render(template, tag, mode, rails):
    validate_tag(tag)
    text = template.replace("${TAG}", tag)
    if mode == "paused":
        return text
    text = text.replace("  replicas: 0\n", "  replicas: 2\n", 1)
    # Scheduling remains suspended until the release's preflight/migration succeeds.
    for rail in sorted(rails):
        flag = RAIL_FLAGS[rail]
        pattern = rf"(?m)^(\s*)- name: {flag}\n\1  value: \"false\"$"
        text, count = re.subn(pattern, rf'\1- name: {flag}\n\1  value: "true"', text)
        if count != 1:
            raise ValueError(f"Expected one disabled flag for {rail}")
    for signer in sorted({RAIL_SIGNERS[rail] for rail in rails}):
        # Place mandatory signing material only into explicitly enabled rails.
        pattern = rf"(?m)^(\s*)- name: X402_{signer}_SIGNER_ADDRESS$"
        match = re.search(pattern, text)
        if not match:
            raise ValueError(f"Missing signer address for {signer}")
        indent = match[1]
        block = (
            f"{indent}- name: X402_{signer}_SIGNER_PRIVATE_KEY\n"
            f"{indent}  valueFrom:\n"
            f"{indent}    secretKeyRef:\n"
            f"{indent}      name: x402-signer-private\n"
            f"{indent}      key: {signer}_SIGNER_PRIVATE_KEY\n"
            f"{indent}      optional: false\n"
        )
        text = text[: match.start()] + block + text[match.start() :]
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", nargs="?", type=Path)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        mode, rails = release_configuration(os.environ)
        if args.check_config:
            validate_tag(os.environ.get("TAG", ""))
            print(mode)
            return
        if args.template is None:
            parser.error("a template is required")
        print(render(args.template.read_text(), os.environ.get("TAG", ""), mode, rails), end="")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
