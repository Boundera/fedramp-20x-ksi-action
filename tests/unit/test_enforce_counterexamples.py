"""SPEC §6/§15.2/§15.4 — every enforce KSI with an evaluator must ship a
compliant fixture that PASSes and a violating fixture that FAILs, for each
provider it supports. A check that cannot fail is not a check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.ksi import load_all
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Disposition, Status
from fedramp_ksi.providers import build_graph
from fedramp_ksi.registry import all_entries, has_evaluator

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

load_all()  # ensure evaluators are registered before collection

_ENFORCE_WITH_EVAL = [
    e.ksi_id
    for e in all_entries()
    if e.disposition is Disposition.ENFORCE and has_evaluator(e.ksi_id)
]


def _dir_name(ksi_id: str) -> str:
    return ksi_id.lower().removeprefix("ksi-")


def _status_for(fixture_path: Path, ksi_id: str) -> Status:
    resources = load_plan_file(fixture_path)
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi_id], target_class=AuthClass.C)
    return er.results[0].status


def test_at_least_one_enforce_evaluator_registered() -> None:
    assert _ENFORCE_WITH_EVAL, "no enforce evaluators registered"


@pytest.mark.parametrize("ksi_id", _ENFORCE_WITH_EVAL)
def test_enforce_ksi_has_pass_and_fail_fixtures(ksi_id: str) -> None:
    dirname = _dir_name(ksi_id)
    provider_dirs = [
        p / dirname
        for p in (FIXTURES / "aws", FIXTURES / "azure", FIXTURES / "gcp")
        if (p / dirname).is_dir()
    ]
    assert provider_dirs, (
        f"{ksi_id}: no fixture directory found (expected .../<provider>/{dirname}/)"
    )

    proved_pass = proved_fail = False
    for d in provider_dirs:
        compliant = d / "compliant.json"
        violating = d / "violating.json"
        assert compliant.is_file(), f"{ksi_id}: missing {compliant}"
        assert violating.is_file(), f"{ksi_id}: missing {violating}"
        if _status_for(compliant, ksi_id) == Status.PASS:
            proved_pass = True
        if _status_for(violating, ksi_id) == Status.FAIL:
            proved_fail = True

    assert proved_pass, f"{ksi_id}: no compliant fixture produced PASS"
    assert proved_fail, f"{ksi_id}: no violating fixture produced FAIL"
