"""End-to-end: a full 46-KSI run is complete, honest, and SDR-conformant."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from fedramp_ksi.app import RunConfig, run
from fedramp_ksi.model import AuthClass, Disposition, Status
from fedramp_ksi.registry import all_entries
from fedramp_ksi.reporters import RunMeta, build_sdr

SDR_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "schemas"
    / "fedramp-security-decision-record-schema-2026-06-24.json"
)

_PLAN = {
    "format_version": "1.2",
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_security_group.web",
                    "type": "aws_security_group",
                    "name": "web",
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "values": {
                        "ingress": [
                            {
                                "from_port": 443,
                                "to_port": 443,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"],
                            }
                        ],
                        "egress": [
                            {
                                "from_port": 443,
                                "to_port": 443,
                                "protocol": "tcp",
                                "cidr_blocks": ["10.0.0.0/8"],
                            }
                        ],
                    },
                },
                {
                    "address": "aws_ebs_volume.d",
                    "type": "aws_ebs_volume",
                    "name": "d",
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "values": {"encrypted": True},
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


def _run(tmp_path) -> object:
    (tmp_path / "plan.json").write_text(json.dumps(_PLAN))
    cfg = RunConfig(
        plan_json=str(tmp_path / "plan.json"),
        target_class=AuthClass.C,
        output_dir=str(tmp_path / "ev"),
        workspace=str(tmp_path),
        meta=RunMeta(generated_at="t"),
    )
    return run(cfg)


def test_all_46_get_a_status_and_no_errors(tmp_path) -> None:
    report = _run(tmp_path).report
    assert len(report.results) == 46
    assert all(r.status != Status.ERROR for r in report.results)


def test_manual_ksis_are_manual(tmp_path) -> None:
    report = _run(tmp_path).report
    manual_ids = {e.ksi_id for e in all_entries() if e.disposition is Disposition.MANUAL}
    for r in report.results:
        if r.ksi_id in manual_ids:
            assert r.status == Status.MANUAL


def test_sdr_all_46_conform(tmp_path) -> None:
    report = _run(tmp_path).report
    full = json.loads(SDR_SCHEMA.read_text())
    item_schema = {
        **full["properties"]["keySecurityIndicators"]["items"]["keySecurityIndicator"],
        "$defs": full["$defs"],
    }
    sdr = build_sdr(report)
    assert len(sdr["keySecurityIndicators"]) == 46
    for item in sdr["keySecurityIndicators"]:
        jsonschema.validate(item, item_schema)


def test_evidence_artifacts_written(tmp_path) -> None:
    paths = _run(tmp_path).artifact_paths
    for key in ("manifest", "sarif", "sdr", "checksums"):
        assert paths[key].exists()
