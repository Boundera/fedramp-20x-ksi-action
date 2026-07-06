"""Advisory control_declared KSIs — PARTIAL when declared, N/A when absent,
never gate-blocking (SPEC §6, §7)."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph


def _plan(*types):
    resources = [
        {
            "address": f"{t}.x",
            "type": t,
            "name": "x",
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "values": {"enable": True} if t == "aws_guardduty_detector" else {},
        }
        for t in types
    ]
    return {"format_version": "1.2", "planned_values": {"root_module": {"resources": resources}}}


def _status(ksi_id, *types):
    er = Engine().evaluate(
        build_graph(load_plan(_plan(*types))), ksi_ids=[ksi_id], target_class=AuthClass.C
    )
    return er.results[0]


@pytest.mark.parametrize(
    "ksi_id,rtype",
    [
        ("KSI-IAM-SUS", "aws_guardduty_detector"),
        ("KSI-INR-AAR", "aws_guardduty_detector"),
        ("KSI-INR-RIR", "aws_securityhub_account"),
        ("KSI-INR-RPI", "aws_inspector2_enabler"),
    ],
)
def test_declared_yields_partial(ksi_id, rtype) -> None:
    r = _status(ksi_id, rtype)
    assert r.status == Status.PARTIAL
    assert r.enforced is False


@pytest.mark.parametrize("ksi_id", ["KSI-IAM-SUS", "KSI-INR-AAR", "KSI-INR-RIR", "KSI-INR-RPI"])
def test_absent_yields_na(ksi_id) -> None:
    r = _status(ksi_id, "aws_s3_bucket")
    assert r.status == Status.NA


def test_advisory_partial_never_blocks_gate() -> None:
    er = Engine().evaluate(
        build_graph(load_plan(_plan("aws_guardduty_detector"))),
        ksi_ids=["KSI-IAM-SUS"],
        target_class=AuthClass.C,
    )
    assert er.advisory_status == Status.PARTIAL
    assert er.enforced_failures == 0
    assert er.gate_status == Status.NA  # no enforce KSIs in scope here
