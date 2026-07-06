"""SPEC §10/§15.7 — gate / fail_on policy."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.gate import decide, parse_fail_on
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Severity
from fedramp_ksi.providers import build_graph
from fedramp_ksi.reporters import RunMeta, build_report

from .conftest import fixture


def _report(name):
    resources = load_plan_file(fixture("aws", "cna-rnt", name))
    er = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    return build_report(er, meta=RunMeta(generated_at="t"))


def test_parse_fail_on() -> None:
    assert parse_fail_on("enforce") == ("enforce", None)
    assert parse_fail_on("none") == ("none", None)
    assert parse_fail_on("severity:high") == ("severity", Severity.HIGH)


def test_parse_fail_on_invalid() -> None:
    with pytest.raises(ValueError):
        parse_fail_on("bogus")


def test_violating_blocks_under_enforce() -> None:
    d = decide(_report("violating.json"), "enforce")
    assert d.blocked is True
    assert d.exit_code == 1


def test_compliant_passes_under_enforce() -> None:
    d = decide(_report("compliant.json"), "enforce")
    assert d.blocked is False
    assert d.exit_code == 0


def test_fail_on_none_never_blocks() -> None:
    d = decide(_report("violating.json"), "none")
    assert d.blocked is False
    assert d.exit_code == 0


def test_fail_on_severity_threshold() -> None:
    # SSH-to-world is high; blocks at severity:high, not at severity:critical.
    assert decide(_report("violating.json"), "severity:high").blocked is True
    assert decide(_report("violating.json"), "severity:critical").blocked is False
