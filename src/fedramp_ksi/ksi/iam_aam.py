"""KSI-IAM-AAM — Automating Account Management (enforce, control_declared).

Accounts are managed with automated guardrails. The IaC-provable control is an
organization Service Control Policy (SCP): when the plan manages IAM users, an
SCP guardrail should be declared.

  - control_declared: an SCP guardrail is present when IAM users are managed.
  - FAIL when IAM users are managed but no SCP is declared; N/A when no IAM users.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "IAM-AAM/scp-guardrail-declared"


@register_evaluator("KSI-IAM-AAM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    users = [
        r
        for r in ctx.graph.resources
        if r.type == "aws_iam_user" and r.provider in ctx.providers_in_scope
    ]
    if not users:
        return []

    scps = [
        g
        for g in ctx.graph.org_guardrails
        if g.kind == "scp" and g.resource.provider in ctx.providers_in_scope
    ]
    if scps:
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                resource_address=scps[0].address,
                message=f"Account guardrail (SCP) declared: {scps[0].address}.",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            message=f"{len(users)} IAM user(s) managed but no organization SCP guardrail is declared.",
            remediation="Declare an aws_organizations_policy (SCP) guardrail (e.g. deny root usage, "
            "restrict regions) to automate account-level controls.",
        )
    ]
