"""SPEC §9/§15.5 — waivers suppress + record; expired waivers reactivate."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from fedramp_ksi.app import RunConfig, run
from fedramp_ksi.model import CheckClass, Finding, Severity, Status
from fedramp_ksi.reporters import RunMeta
from fedramp_ksi.waivers import (
    Waiver,
    baseline_transform,
    build_baseline,
    load_waivers,
    waiver_transform,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _fail(ksi="KSI-CNA-RNT", resource="aws_security_group.bastion") -> Finding:
    return Finding(
        ksi_id=ksi,
        check_id=f"{ksi}/x",
        check_class=CheckClass.ANTI_PATTERN_ABSENT,
        severity=Severity.HIGH,
        status=Status.FAIL,
        message="boom",
        resource_address=resource,
    )


def test_active_waiver_suppresses() -> None:
    w = Waiver("KSI-CNA-RNT", "aws_security_group.bastion", "vpn only", "j@x.com", date(2099, 1, 1))
    out = waiver_transform([w], date(2026, 6, 30))([_fail()])
    assert out[0].suppressed
    assert out[0].waiver_ref and "j@x.com" in out[0].waiver_ref


def test_expired_waiver_does_not_suppress() -> None:
    w = Waiver("KSI-CNA-RNT", "aws_security_group.bastion", "old", "j@x.com", date(2025, 1, 1))
    out = waiver_transform([w], date(2026, 6, 30))([_fail()])
    assert not out[0].suppressed


def test_glob_resource_match() -> None:
    w = Waiver("KSI-CNA-RNT", "module.*.aws_security_group.*", "r", "j@x.com", date(2099, 1, 1))
    f = _fail(resource="module.net.aws_security_group.db")
    out = waiver_transform([w], date(2026, 6, 30))([f])
    assert out[0].suppressed


def test_unmatched_waiver_leaves_finding_live() -> None:
    w = Waiver("KSI-MLA-EVC", "aws_x.y", "r", "j@x.com", date(2099, 1, 1))
    out = waiver_transform([w], date(2026, 6, 30))([_fail()])
    assert not out[0].suppressed


def test_load_waivers_yaml(tmp_path) -> None:
    (tmp_path / "w.yml").write_text(
        "waivers:\n"
        "  - ksi: KSI-CNA-RNT\n"
        "    resource: aws_security_group.bastion\n"
        "    reason: VPN only\n"
        "    approved_by: jane@corp.com\n"
        "    expires: 2099-09-30\n"
    )
    waivers = load_waivers(tmp_path / "w.yml")
    assert len(waivers) == 1
    assert waivers[0].approved_by == "jane@corp.com"


def test_baseline_suppresses_known_findings() -> None:
    findings = [_fail()]
    fps = set(build_baseline(findings))
    out = baseline_transform(fps)(findings)
    assert out[0].baselined
    # A new finding not in the baseline stays live (drift).
    new = _fail(resource="aws_security_group.new")
    assert not baseline_transform(fps)([new])[0].suppressed


def test_waiver_end_to_end_unblocks_gate(tmp_path) -> None:
    # A waiver for the violating SG downgrades the gate from FAIL to non-blocking.
    (tmp_path / ".fedramp-ksi-waivers.yml").write_text(
        "waivers:\n"
        "  - ksi: KSI-CNA-RNT\n"
        "    resource: aws_security_group.bastion\n"
        "    reason: legacy VPN bastion, JIRA SEC-1\n"
        "    approved_by: jane@corp.com\n"
        "    expires: 2099-01-01\n"
    )
    cfg = RunConfig(
        plan_json=str(FIXTURES / "aws" / "cna-rnt" / "violating.json"),
        ksi_ids=("KSI-CNA-RNT",),
        output_dir=str(tmp_path / "ev"),
        workspace=str(tmp_path),
        today="2026-06-30",
        meta=RunMeta(generated_at="t"),
    )
    result = run(cfg)
    assert result.report.enforced_failures == 0
    assert result.decision.blocked is False
    # The waiver is recorded in the manifest for auditor review.
    assert result.report.suppressed_findings
