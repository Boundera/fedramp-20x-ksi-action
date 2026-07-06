"""KSI-RPL-ARP — Aligning Recovery Plan (enforce, control_declared).

DR infrastructure is declared. The IaC-provable control is a backup plan or
cross-region replication when stateful resources are managed.

  - control_declared: a backup plan / replication is present when stateful
    resources (DB / S3) are managed.
  - FAIL when stateful resources exist without DR infra; N/A when none.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "RPL-ARP/dr-infra-declared"
_STATEFUL = {"aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_dynamodb_table"}


@register_evaluator("KSI-RPL-ARP")
def evaluate(ctx: EvalContext) -> list[Finding]:
    stateful = [
        r
        for r in ctx.graph.resources
        if r.type in _STATEFUL and r.provider in ctx.providers_in_scope
    ]
    if not stateful:
        return []

    has_backup_plan = any(
        r.type == "aws_backup_plan"
        for r in ctx.graph.resources
        if r.provider in ctx.providers_in_scope
    )
    has_replication = any(
        r.get("replication_configuration") for r in stateful if r.type == "aws_s3_bucket"
    )
    if has_backup_plan or has_replication:
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                message="Recovery infrastructure declared (backup plan or cross-region replication).",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            message=f"{len(stateful)} stateful resource(s) managed but no DR infrastructure "
            "(aws_backup_plan or replication) is declared.",
            remediation="Declare an aws_backup_plan or cross-region replication aligned to your recovery objectives.",
        )
    ]
