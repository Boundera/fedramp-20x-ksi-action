"""Golden fixtures for the logging enforce KSIs: MLA-LET, MLA-OSM, CMT-LMC."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan, load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture

_CASES = [
    ("KSI-MLA-LET", "mla-let"),
    ("KSI-MLA-OSM", "mla-osm"),
    ("KSI-CMT-LMC", "cmt-lmc"),
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


@pytest.mark.parametrize("ksi_id", ["KSI-MLA-LET", "KSI-MLA-OSM"])
def test_no_trail_is_na(ksi_id) -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    er = Engine().evaluate(build_graph(load_plan(plan)), ksi_ids=[ksi_id], target_class=AuthClass.C)
    assert er.results[0].status == Status.NA


def test_cmt_lmc_config_recorder_also_satisfies() -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.d",
                        "type": "aws_s3_bucket",
                        "name": "d",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"bucket": "d"},
                    },
                    {
                        "address": "aws_config_configuration_recorder.r",
                        "type": "aws_config_configuration_recorder",
                        "name": "r",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {},
                    },
                ]
            }
        },
    }
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-CMT-LMC"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.PASS
