"""Golden fixtures for the final AWS enforce KSIs (IAM/PIY/RPL/SCR/SVC)."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    ("KSI-IAM-JIT", "iam-jit"),
    ("KSI-IAM-AAM", "iam-aam"),
    ("KSI-IAM-APM", "iam-apm"),
    ("KSI-PIY-GIV", "piy-giv"),
    ("KSI-RPL-ARP", "rpl-arp"),
    ("KSI-SCR-MIT", "scr-mit"),
    ("KSI-SVC-ACM", "svc-acm"),
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


def test_all_22_enforce_ksis_have_evaluators() -> None:
    # Every base-enforce KSI is now implemented (full AWS enforce-set).
    from fedramp_ksi.ksi import load_all
    from fedramp_ksi.model import Disposition
    from fedramp_ksi.registry import all_entries, has_evaluator

    load_all()
    missing = [
        e.ksi_id
        for e in all_entries()
        if e.disposition is Disposition.ENFORCE and not has_evaluator(e.ksi_id)
    ]
    assert missing == [], f"enforce KSIs without evaluators: {missing}"
