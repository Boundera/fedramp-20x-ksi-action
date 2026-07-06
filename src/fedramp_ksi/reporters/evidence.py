"""Evidence pack + manifest + FedRAMP SDR output (SPEC §4, §8, §15.8).

Produces:
  - a deterministic ``manifest.json`` (same inputs ⇒ byte-identical, timestamps
    aside) recording every KSI disposition/status, findings, applied waivers,
    and the pinned ruleset version + SHA-256;
  - ``sdr.json``: a FedRAMP Security Decision Record ``keySecurityIndicators``
    array conforming to the bundled SDR schema (see docs/DECISIONS.md D3);
  - ``CHECKSUMS.sha256`` over every artifact for tamper-evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..model import KSIResult, Status
from ..ruleset import Ruleset, load_ruleset
from .report import RunReport
from .sarif import build_sarif

MANIFEST_SCHEMA_VERSION = "3.0"


def build_manifest(report: RunReport) -> dict[str, Any]:
    """Build the deterministic evidence manifest (excluding timestamps)."""
    waivers_applied = [
        {
            "ksi_id": f.ksi_id,
            "resource": f.resource_address,
            "check_id": f.check_id,
            "waiver_ref": f.waiver_ref,
            "baselined": f.baselined,
        }
        for f in report.suppressed_findings
    ]
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "action": "Boundera/fedramp-20x-ksi-action",
        "action_version": report.meta.action_version,
        "ruleset": {
            "version": report.ruleset_version,
            "sha256": report.ruleset_sha256,
            "source_file": report.ruleset_source_file,
        },
        "target_class": report.target_class.value,
        "repository": report.meta.repository,
        "commit_sha": report.meta.commit_sha,
        "trigger_event": report.meta.trigger_event,
        "gate": {
            "status": report.gate_status.value,
            "advisory_status": report.advisory_status.value,
            "enforced_failures": report.enforced_failures,
        },
        "findings_by_severity": report.findings_by_severity(),
        "ksi_results": [r.as_dict() for r in report.results],
        "waivers_applied": waivers_applied,
    }


def build_sdr(report: RunReport, ruleset: Ruleset | None = None) -> dict[str, Any]:
    """Build a FedRAMP SDR ``keySecurityIndicators`` document."""
    rs = ruleset or load_ruleset()
    return {"keySecurityIndicators": [_sdr_item(r, rs) for r in report.results]}


def _sdr_item(r: KSIResult, rs: Ruleset) -> dict[str, Any]:
    ksi_def = rs.ksis.get(r.ksi_id)
    controls = ", ".join(ksi_def.controls) if ksi_def else ""
    tests = sorted({f.check_id for f in r.findings}) or [f"{r.ksi_id}/disposition"]
    evidence = [
        {
            "evidenceType": "Configuration",
            "evidenceDescription": (
                f"Terraform plan evaluation of {r.ksi_id} ({r.disposition}); status {r.status.value}."
            ),
            "evidenceText": _evidence_text(r),
            "lastUpdated": rs.last_updated,
        }
    ]
    return {
        "ksiId": r.ksi_id,
        "ksiImplementation": [
            f"{r.name}. Related NIST 800-53: {controls or 'n/a'}. Disposition: {r.disposition}."
        ],
        "ksiValidation": [
            "Validated by the fedramp-20x-ksi-action gate against the resolved "
            f"`terraform show -json` plan (ruleset {rs.version}). Result: {r.status.value}."
        ],
        "ksiAssesment": [
            "Independent assessment pending 3PAO review of the attached evidence pack."
            if r.status != Status.MANUAL
            else "Manual KSI — evidence maintained outside IaC; see external evidence pointer."
        ],
        "ksiTests": tests,
        "ksiEvidence": evidence,
    }


def _evidence_text(r: KSIResult) -> str:
    if not r.findings:
        return f"{r.status.value}: {r.notes or 'no in-scope resources'}"
    lines = [f"{r.status.value} — {r.name}"]
    for f in r.findings:
        tag = f.status.value + (" [waived]" if f.suppressed else "")
        lines.append(f"  [{tag}] {f.message}")
    return "\n".join(lines)


def _dumps(obj: dict[str, Any]) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_evidence_pack(
    report: RunReport,
    output_dir: str | Path,
    ruleset: Ruleset | None = None,
) -> dict[str, Path]:
    """Write manifest/sarif/sdr + checksums into ``output_dir``. Returns paths."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(report)
    manifest_with_ts = {**manifest, "generated_at": report.meta.generated_at}
    sarif = build_sarif(report)
    sdr = build_sdr(report, ruleset)

    paths = {
        "manifest": out / "manifest.json",
        "sarif": out / "fedramp-ksi.sarif",
        "sdr": out / "sdr.json",
    }
    paths["manifest"].write_text(_dumps(manifest_with_ts), encoding="utf-8")
    paths["sarif"].write_text(_dumps(sarif), encoding="utf-8")
    paths["sdr"].write_text(_dumps(sdr), encoding="utf-8")

    # Checksums over the content-bearing artifacts (deterministic order).
    checksum_lines = []
    for name in ("manifest.json", "fedramp-ksi.sarif", "sdr.json"):
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        checksum_lines.append(f"{digest}  {name}")
    checksums_path = out / "CHECKSUMS.sha256"
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    paths["checksums"] = checksums_path
    return paths
