"""SARIF 2.1.0 reporter (SPEC §4, §11).

Emits a SARIF log that validates against the 2.1.0 schema and surfaces in GitHub
code scanning. Each check_id becomes a reportingDescriptor (rule); each live
FAIL/ERROR/PARTIAL finding becomes a result. Waived/baselined findings are
emitted with a SARIF ``suppressions`` entry so they remain visible but do not
alarm. The resolved ruleset version + hash are recorded on the run.
"""

from __future__ import annotations

from typing import Any

from ..model import Finding, Severity, Status
from .report import RunReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL_BY_STATUS = {
    Status.FAIL: "error",
    Status.ERROR: "error",
    Status.PARTIAL: "warning",
    Status.PASS: "note",
    Status.NA: "none",
    Status.MANUAL: "none",
}


def _level(finding: Finding) -> str:
    if finding.status == Status.FAIL and finding.severity in (Severity.LOW, Severity.MEDIUM):
        return "warning"
    return _LEVEL_BY_STATUS.get(finding.status, "warning")


def _reportable(finding: Finding) -> bool:
    return finding.status in (Status.FAIL, Status.ERROR, Status.PARTIAL)


def build_sarif(report: RunReport) -> dict[str, Any]:
    findings = [f for f in report.all_findings if _reportable(f)]

    # One rule per distinct check_id.
    rules_by_id: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.check_id not in rules_by_id:
            rules_by_id[f.check_id] = {
                "id": f.check_id,
                "name": f.check_id.replace("/", "_"),
                "shortDescription": {"text": f"{f.ksi_id} — {f.check_class.value}"},
                "properties": {
                    "ksi_id": f.ksi_id,
                    "check_class": f.check_class.value,
                    "security-severity": _security_severity(f.severity),
                },
            }

    results = [_result(f) for f in findings]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fedramp-20x-ksi-action",
                        "informationUri": "https://github.com/Boundera/fedramp-20x-ksi-action",
                        "version": report.meta.action_version,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "properties": {
                    "ruleset_version": report.ruleset_version,
                    "ruleset_sha256": report.ruleset_sha256,
                    "target_class": report.target_class.value,
                },
                "results": results,
            }
        ],
    }


def _result(f: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": f.check_id,
        "level": _level(f),
        "message": {"text": f.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.source.file or "terraform"},
                    **({"region": {"startLine": f.source.line}} if f.source.line else {}),
                },
                "logicalLocations": [
                    {"fullyQualifiedName": f.resource_address or f.ksi_id, "kind": "resource"}
                ],
            }
        ],
        "properties": {"ksi_id": f.ksi_id, "status": f.status.value, "severity": f.severity.value},
    }
    if f.suppressed:
        kind = "external" if f.waiver_ref else "inSource"
        justification = f.waiver_ref or "baseline"
        result["suppressions"] = [{"kind": kind, "justification": justification}]
    return result


def _security_severity(sev: Severity) -> str:
    # GitHub code scanning numeric severity (0-10).
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
    }[sev]
