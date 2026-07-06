"""KSI-CNA-OFA — Optimizing for Availability (enforce, configured_correctly).

Redundancy/HA is declared. The IaC-provable signal is multi-AZ on managed
databases.

  - configured_correctly: multi-AZ-capable databases enable multi_az.
  - FAIL when a database sets multi_az = false; N/A when none in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-OFA/multi-az"
_MULTI_AZ_TYPES = {"aws_db_instance", "aws_rds_cluster"}


@register_evaluator("KSI-CNA-OFA")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [
        r
        for r in ctx.graph.resources
        if r.type in _MULTI_AZ_TYPES and r.provider in ctx.providers_in_scope
    ]
    known = [r for r in scoped if not r.is_unknown("multi_az")]
    # aws_rds_cluster is inherently multi-AZ; only aws_db_instance carries multi_az.
    known = [r for r in known if r.type == "aws_db_instance"]
    if not known:
        return []

    findings: list[Finding] = []
    for r in known:
        if not bool(r.get("multi_az")):
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: multi_az = false — no cross-AZ redundancy.",
                    remediation="Set multi_az = true for production databases to survive an AZ failure.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(known)} database(s) enable multi-AZ redundancy.",
            )
        )
    return findings
