"""Remaining advisory KSIs — PARTIAL when infra declared, else N/A."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph


def _plan(*types):
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": f"{t}.x",
                        "type": t,
                        "name": "x",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"name": "x"},
                    }
                    for t in types
                ]
            }
        },
    }


def _status(ksi_id, *types):
    er = Engine().evaluate(
        build_graph(load_plan(_plan(*types))), ksi_ids=[ksi_id], target_class=AuthClass.C
    )
    return er.results[0].status


@pytest.mark.parametrize(
    "ksi_id,rtype",
    [
        ("KSI-CNA-RVP", "aws_wafv2_web_acl"),
        ("KSI-MLA-RVL", "aws_cloudtrail"),
        ("KSI-SVC-VRI", "aws_signer_signing_profile"),
        ("KSI-CMT-VTD", "aws_ssm_patch_baseline"),
        ("KSI-SCR-MON", "aws_inspector2_enabler"),
    ],
)
def test_declared_partial(ksi_id, rtype) -> None:
    assert _status(ksi_id, rtype) == Status.PARTIAL


@pytest.mark.parametrize(
    "ksi_id", ["KSI-CNA-RVP", "KSI-MLA-RVL", "KSI-SVC-VRI", "KSI-CMT-VTD", "KSI-SCR-MON"]
)
def test_absent_na(ksi_id) -> None:
    assert _status(ksi_id, "aws_s3_bucket") == Status.NA


def test_all_34_iac_ksis_have_evaluators() -> None:
    """Every enforce + advisory KSI now has an evaluator (all 12 manual are
    handled by the engine directly)."""
    from fedramp_ksi.ksi import load_all
    from fedramp_ksi.model import Disposition
    from fedramp_ksi.registry import all_entries, has_evaluator

    load_all()
    missing = [
        e.ksi_id
        for e in all_entries()
        if e.disposition in (Disposition.ENFORCE, Disposition.ADVISORY)
        and not has_evaluator(e.ksi_id)
    ]
    assert missing == [], f"non-manual KSIs without evaluators: {missing}"
