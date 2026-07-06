"""SPEC §15.11 — COVERAGE.md is generated from the registry and stays in sync."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_coverage_doc", ROOT / "tools" / "gen_coverage_doc.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_coverage_doc_matches_registry() -> None:
    gen = _load_generator()
    expected = gen.render()
    actual = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert actual == expected, "docs/COVERAGE.md is stale — run: python tools/gen_coverage_doc.py"


def test_coverage_doc_lists_all_46() -> None:
    text = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert text.count("| `KSI-") == 46
