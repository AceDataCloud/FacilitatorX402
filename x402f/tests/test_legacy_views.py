"""Collect the legacy Django TestCase module shadowed by the tests package."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parents[1] / "tests.py"
_SPEC = importlib.util.spec_from_file_location("x402f_legacy_view_tests", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

X402MultichainViewTests = _MODULE.X402MultichainViewTests
