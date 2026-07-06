"""Golden fixtures for CNA-MAT, RPL-ABO, SVC-ASM enforce KSIs."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan, load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    ("KSI-CNA-MAT", "cna-mat"),
    ("KSI-RPL-ABO", "rpl-abo"),
    ("KSI-SVC-ASM", "svc-asm"),
]


def _status(ksi_id, fixdir, name):
    resources = load_plan_file(fixture("aws", fixdir, name))
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi_id], target_class=AuthClass.C)
    return er.results[0]


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_compliant_passes(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "compliant.json").status == Status.PASS


@pytest.mark.parametrize("ksi_id,fixdir", _CASES)
def test_violating_fails(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "violating.json").status == Status.FAIL


def test_cna_mat_allows_web_ports_but_not_rnt_would_miss() -> None:
    # 8080-to-world is NOT an RNT sensitive port, but MAT flags it as over-exposure.
    rnt = _status("KSI-CNA-RNT", "cna-mat", "violating.json")
    mat = _status("KSI-CNA-MAT", "cna-mat", "violating.json")
    assert rnt.status == Status.PASS  # RNT doesn't consider 8080 sensitive
    assert mat.status == Status.FAIL  # MAT flags unnecessary exposure


def test_svc_asm_unknown_password_is_not_hardcoded() -> None:
    assert _status("KSI-SVC-ASM", "svc-asm", "compliant.json").status == Status.PASS


def test_rpl_abo_na_without_backup_resources() -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-RPL-ABO"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.NA
