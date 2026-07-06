"""Class-C shifters CNA-EIS, MLA-ALA, SVC-VCM: advisory@B, enforce@C (SPEC §7)."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    ("KSI-CNA-EIS", "cna-eis"),
    ("KSI-MLA-ALA", "mla-ala"),
    ("KSI-SVC-VCM", "svc-vcm"),
]


def _eval(ksi_id, fixdir, name, cls=AuthClass.C):
    resources = load_plan_file(fixture("aws", fixdir, name))
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi_id], target_class=cls)
    return er


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_compliant_passes(ksi_id, fixdir) -> None:
    assert _eval(ksi_id, fixdir, "compliant.json").results[0].status == Status.PASS


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_violating_fails(ksi_id, fixdir) -> None:
    assert _eval(ksi_id, fixdir, "violating.json").results[0].status == Status.FAIL


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_violating_blocks_only_at_class_c(ksi_id, fixdir) -> None:
    # Class B: advisory ⇒ not gate-blocking. Class C: enforce ⇒ gate-blocking.
    er_b = _eval(ksi_id, fixdir, "violating.json", cls=AuthClass.B)
    er_c = _eval(ksi_id, fixdir, "violating.json", cls=AuthClass.C)
    assert er_b.results[0].enforced is False
    assert er_b.enforced_failures == 0
    assert er_c.results[0].enforced is True
    assert er_c.enforced_failures >= 1
