"""SPEC §15.7 — end-to-end: a violating plan blocks, a compliant plan passes,
and artifacts (manifest/sarif/sdr/checksums) are produced."""

from __future__ import annotations

from pathlib import Path

from fedramp_ksi.app import RunConfig, run
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.reporters import RunMeta

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _cfg(fixture_name: str, out: Path, **kw) -> RunConfig:
    return RunConfig(
        plan_json=str(FIXTURES / "aws" / "cna-rnt" / fixture_name),
        ksi_ids=("KSI-CNA-RNT",),
        target_class=AuthClass.C,
        output_dir=str(out),
        meta=RunMeta(generated_at="2026-01-01T00:00:00Z"),
        **kw,
    )


def test_violating_plan_blocks_and_writes_artifacts(tmp_path) -> None:
    result = run(_cfg("violating.json", tmp_path))
    assert result.report.gate_status == Status.FAIL
    assert result.decision.blocked is True
    assert result.decision.exit_code == 1
    for key in ("manifest", "sarif", "sdr", "checksums"):
        assert result.artifact_paths[key].exists()


def test_compliant_plan_passes(tmp_path) -> None:
    result = run(_cfg("compliant.json", tmp_path))
    assert result.report.gate_status == Status.PASS
    assert result.decision.blocked is False
    assert result.decision.exit_code == 0


def test_report_only_mode_does_not_block(tmp_path) -> None:
    result = run(_cfg("violating.json", tmp_path, fail_on="none"))
    assert result.decision.blocked is False
    assert result.decision.exit_code == 0


def test_all_46_ksis_evaluated_when_unrestricted(tmp_path) -> None:
    cfg = RunConfig(
        plan_json=str(FIXTURES / "aws" / "cna-rnt" / "compliant.json"),
        target_class=AuthClass.C,
        output_dir=str(tmp_path),
        meta=RunMeta(generated_at="t"),
    )
    result = run(cfg)
    assert len(result.report.results) == 46
