"""SPEC §6 / §15.4 — honest-status hard rules, enforced and unit-tested."""

from __future__ import annotations

import pytest

from fedramp_ksi import registry
from fedramp_ksi.engine import Engine, StatusPolicyError, rollup_status, validate_findings
from fedramp_ksi.engine.status import allowed_statuses
from fedramp_ksi.model import (
    AuthClass,
    CheckClass,
    Disposition,
    Finding,
    Provider,
    Severity,
    Status,
)
from fedramp_ksi.model.graph import ResourceGraph
from fedramp_ksi.model.resources import Resource


def _finding(ksi_id: str, status: Status, suppressed: bool = False) -> Finding:
    f = Finding(
        ksi_id=ksi_id,
        check_id=f"{ksi_id}/x",
        check_class=CheckClass.CONFIGURED_CORRECTLY,
        severity=Severity.HIGH,
        status=status,
        message="m",
    )
    return f.with_baseline() if suppressed else f


@pytest.fixture
def temp_evaluator():
    """Register/unregister an evaluator for a KSI id for the duration of a test."""
    registered: list[str] = []

    def _register(ksi_id, fn):
        registry._EVALUATORS[ksi_id] = fn
        registered.append(ksi_id)

    yield _register
    for k in registered:
        registry._EVALUATORS.pop(k, None)


# --- allowed status sets ----------------------------------------------------


def test_enforce_cannot_emit_partial() -> None:
    assert Status.PARTIAL not in allowed_statuses(Disposition.ENFORCE)


def test_advisory_allows_partial() -> None:
    assert Status.PARTIAL in allowed_statuses(Disposition.ADVISORY)


def test_manual_only_manual_or_na() -> None:
    assert allowed_statuses(Disposition.MANUAL) == frozenset({Status.MANUAL, Status.NA})


def test_validate_findings_rejects_enforce_partial() -> None:
    with pytest.raises(StatusPolicyError):
        validate_findings(Disposition.ENFORCE, [_finding("KSI-CNA-RNT", Status.PARTIAL)])


def test_validate_findings_rejects_manual_pass() -> None:
    with pytest.raises(StatusPolicyError):
        validate_findings(Disposition.MANUAL, [_finding("KSI-CED-RAT", Status.PASS)])


# --- roll-up ----------------------------------------------------------------


def test_rollup_empty_is_na() -> None:
    assert rollup_status([]) == Status.NA


def test_rollup_all_suppressed_is_na() -> None:
    fs = [_finding("KSI-CNA-RNT", Status.FAIL, suppressed=True)]
    assert rollup_status(fs) == Status.NA


def test_rollup_worst_wins() -> None:
    fs = [
        _finding("KSI-CNA-RNT", Status.PASS),
        _finding("KSI-CNA-RNT", Status.FAIL),
    ]
    assert rollup_status(fs) == Status.FAIL


# --- engine behavior --------------------------------------------------------


def test_manual_ksi_returns_manual() -> None:
    res = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-CED-RAT"], target_class=AuthClass.C)
    r = res.results[0]
    assert r.status == Status.MANUAL
    assert r.enforced is False


def test_enforce_ksi_without_evaluator_is_na_not_fail() -> None:
    # No-resources / not-implemented ⇒ N/A, never FAIL/ERROR (SPEC §6).
    res = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-CNA-ULN"], target_class=AuthClass.C)
    assert res.results[0].status == Status.NA


def test_evaluator_crash_becomes_error(temp_evaluator) -> None:
    def boom(ctx):
        raise RuntimeError("adapter blew up")

    temp_evaluator("KSI-CNA-MAT", boom)
    res = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-CNA-MAT"], target_class=AuthClass.C)
    assert res.results[0].status == Status.ERROR
    assert res.results[0].enforced is True


def test_enforce_evaluator_emitting_partial_becomes_error(temp_evaluator) -> None:
    def bad(ctx):
        return [_finding("KSI-CNA-MAT", Status.PARTIAL)]

    temp_evaluator("KSI-CNA-MAT", bad)
    res = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-CNA-MAT"], target_class=AuthClass.C)
    assert res.results[0].status == Status.ERROR


def test_enforced_failures_counted_and_gate_blocks(temp_evaluator) -> None:
    graph = ResourceGraph(resources=[Resource(address="a", type="t", provider=Provider.AWS)])

    def fail_eval(ctx):
        return [_finding("KSI-CNA-MAT", Status.FAIL)]

    temp_evaluator("KSI-CNA-MAT", fail_eval)
    res = Engine().evaluate(graph, ksi_ids=["KSI-CNA-MAT"], target_class=AuthClass.C)
    assert res.results[0].status == Status.FAIL
    assert res.enforced_failures == 1
    assert res.gate_status == Status.FAIL


def test_advisory_fail_does_not_count_as_enforced_failure(temp_evaluator) -> None:
    def fail_eval(ctx):
        return [_finding("KSI-CNA-RVP", Status.FAIL)]

    temp_evaluator("KSI-CNA-RVP", fail_eval)
    res = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-CNA-RVP"], target_class=AuthClass.C)
    assert res.results[0].status == Status.FAIL
    assert res.results[0].enforced is False
    assert res.enforced_failures == 0


def test_class_c_shift_makes_vcm_enforced(temp_evaluator) -> None:
    def fail_eval(ctx):
        return [_finding("KSI-SVC-VCM", Status.FAIL)]

    temp_evaluator("KSI-SVC-VCM", fail_eval)
    # Advisory at B → not enforced; enforce at C → enforced.
    res_b = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-SVC-VCM"], target_class=AuthClass.B)
    res_c = Engine().evaluate(ResourceGraph(), ksi_ids=["KSI-SVC-VCM"], target_class=AuthClass.C)
    assert res_b.results[0].enforced is False
    assert res_c.results[0].enforced is True
    assert res_c.enforced_failures == 1
