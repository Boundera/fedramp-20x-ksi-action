"""KSI-MLA-EVC golden fixtures + regression (SPEC §15.12)."""

from __future__ import annotations

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan, load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture


def _status(fixture_name):
    resources = load_plan_file(fixture("aws", "mla-evc", fixture_name))
    er = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-MLA-EVC"], target_class=AuthClass.C
    )
    return er.results[0]


def test_config_recorder_declared_passes() -> None:
    r = _status("compliant.json")
    assert r.status == Status.PASS


def test_no_recorder_with_resources_fails() -> None:
    r = _status("violating.json")
    assert r.status == Status.FAIL
    assert any("configuration-evaluation" in f.message for f in r.fail_findings)


def test_no_resources_is_na() -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-MLA-EVC"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.NA
