"""KSI-IAM-JIT — Authorizing Just-in-Time (enforce, anti_pattern_absent).

No standing administrative access. The IaC-provable anti-pattern is the AWS
managed AdministratorAccess policy attached directly to an IAM *user* (a
permanent human admin), rather than assumed just-in-time via a role.

  - anti_pattern_absent: AdministratorAccess is not attached to any IAM user.
  - PASS when user policy attachments exist without standing admin; N/A when none.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "IAM-JIT/no-standing-admin"
_ATTACH_TYPES = {"aws_iam_user_policy_attachment"}


def _is_admin(arn: str) -> bool:
    return arn.endswith(":policy/AdministratorAccess") or arn.endswith("/AdministratorAccess")


@register_evaluator("KSI-IAM-JIT")
def evaluate(ctx: EvalContext) -> list[Finding]:
    attachments = [
        r
        for r in ctx.graph.resources
        if r.type in _ATTACH_TYPES and r.provider in ctx.providers_in_scope
    ]
    if not attachments:
        return []

    findings: list[Finding] = []
    for r in attachments:
        arn = str(r.get("policy_arn", ""))
        if _is_admin(arn):
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.ANTI_PATTERN_ABSENT,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: AdministratorAccess is attached directly to an IAM user (standing admin).",
                    remediation="Grant admin just-in-time via an assumable role with session limits and "
                    "permission boundaries; do not attach AdministratorAccess to users.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.ANTI_PATTERN_ABSENT,
                status=Status.PASS,
                message=f"No standing admin across {len(attachments)} user policy attachment(s).",
            )
        )
    return findings
