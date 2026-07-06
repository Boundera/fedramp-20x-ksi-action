"""KSI-RPL-ABO — Aligning Backups with Objectives (enforce, configured_correctly).

Statement (2026.06.24.01): backups are performed and aligned to recovery
objectives.

The IaC-provable portion is that backup-capable resources actually enable
backups (with non-zero retention where a retention value exists).

  - configured_correctly: every in-scope backup-capable resource has backups
    enabled. FAIL when a resource explicitly disables backups (retention 0 /
    PITR off). N/A when there are no backup-capable resources in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "RPL-ABO/backups-enabled"


@register_evaluator("KSI-RPL-ABO")
def evaluate(ctx: EvalContext) -> list[Finding]:
    backups = [b for b in ctx.graph.backups if b.resource.provider in ctx.providers_in_scope]
    known = [b for b in backups if b.enabled is not None]
    if not known:
        return []  # N/A

    findings: list[Finding] = []
    for b in known:
        if b.enabled is False:
            detail = (
                " (backup_retention_period = 0)"
                if b.retention_days == 0
                else " (recovery/PITR disabled)"
            )
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=b.address,
                    source=b.resource.source,
                    message=f"{b.address}: backups are disabled{detail}.",
                    remediation="Enable backups with retention aligned to your RPO "
                    "(e.g. backup_retention_period ≥ 7, or enable point-in-time recovery).",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(known)} backup-capable resource(s) enable backups.",
            )
        )
    return findings
