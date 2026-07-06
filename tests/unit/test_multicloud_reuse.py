"""Provider-agnostic evaluators run on Azure/GCP with no code changes (SPEC §5).

CNA-MAT / CNA-DFP (NetworkRule) and SVC-ASM (secret detection) reuse the same
evaluator across clouds — only fixtures differ.
"""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    (cloud, ksi, fixdir)
    for cloud in ("azure", "gcp")
    for ksi, fixdir in [
        ("KSI-CNA-MAT", "cna-mat"),
        ("KSI-CNA-DFP", "cna-dfp"),
        ("KSI-SVC-ASM", "svc-asm"),
    ]
] + [
    # CNA-ULN generalized to Azure DB servers via the public-flag table.
    ("azure", "KSI-CNA-ULN", "cna-uln"),
]


def _status(cloud, ksi, fixdir, name):
    resources = load_plan_file(fixture(cloud, fixdir, name))
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi], target_class=AuthClass.C)
    return er.results[0].status


@pytest.mark.parametrize("cloud,ksi,fixdir", _CASES)
def test_compliant_passes(cloud, ksi, fixdir) -> None:
    assert _status(cloud, ksi, fixdir, "compliant.json") == Status.PASS


@pytest.mark.parametrize("cloud,ksi,fixdir", _CASES)
def test_violating_fails(cloud, ksi, fixdir) -> None:
    assert _status(cloud, ksi, fixdir, "violating.json") == Status.FAIL
