"""Golden fixtures for CNA architecture enforce KSIs: ULN, DFP, OFA, IBP."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    ("KSI-CNA-ULN", "cna-uln"),
    ("KSI-CNA-DFP", "cna-dfp"),
    ("KSI-CNA-OFA", "cna-ofa"),
    ("KSI-CNA-IBP", "cna-ibp"),
]


def _status(ksi_id, fixdir, name):
    resources = load_plan_file(fixture("aws", fixdir, name))
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi_id], target_class=AuthClass.C)
    return er.results[0].status


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_compliant_passes(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "compliant.json") == Status.PASS


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_violating_fails(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "violating.json") == Status.FAIL
