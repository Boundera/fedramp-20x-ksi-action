"""SPEC §11 — KSI-CNA-RNT golden fixtures: compliant⇒PASS, violating⇒FAIL."""

from __future__ import annotations

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture


def _evaluate(fixture_path) -> object:
    resources = load_plan_file(fixture_path)
    graph = build_graph(resources)
    res = Engine().evaluate(graph, ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C)
    return res.results[0]


def test_compliant_plan_passes() -> None:
    r = _evaluate(fixture("aws", "cna-rnt", "compliant.json"))
    assert r.status == Status.PASS
    assert r.fail_findings == ()


def test_violating_plan_fails() -> None:
    r = _evaluate(fixture("aws", "cna-rnt", "violating.json"))
    assert r.status == Status.FAIL
    # SSH (22) open to the world is the anti-pattern.
    msgs = " ".join(f.message for f in r.fail_findings)
    assert "22" in msgs and "SSH" in msgs


def test_violating_plan_is_gate_blocking() -> None:
    resources = load_plan_file(fixture("aws", "cna-rnt", "violating.json"))
    res = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    assert res.enforced_failures >= 1
    assert res.gate_status == Status.FAIL


def test_module_nested_violation_is_caught() -> None:
    r = _evaluate(fixture("aws", "cna-rnt", "module_nested_violation.json"))
    assert r.status == Status.FAIL
    addrs = {f.resource_address for f in r.fail_findings}
    assert 'module.network.module.sg["prod"].aws_security_group.db' in addrs
    # RDP (3389) is the exposed port.
    assert any("3389" in f.message for f in r.fail_findings)


def test_no_network_resources_is_na() -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    from fedramp_ksi.loader import load_plan

    res = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    assert res.results[0].status == Status.NA
