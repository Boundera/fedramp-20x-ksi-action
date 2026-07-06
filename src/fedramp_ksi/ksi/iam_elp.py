"""KSI-IAM-ELP — Ensuring Least Privilege (enforce, anti_pattern_absent).

Statement (2026.06.24.01): access is limited to the least privilege necessary.

The IaC-provable anti-pattern is an admin wildcard grant: an Allow statement
with both ``Action: "*"`` (or ``"*:*"``) and ``Resource: "*"``. Such a policy is
the opposite of least privilege and can always fail a build.

  - anti_pattern_absent: no Allow statement grants wildcard action on wildcard
    resource.
  - PASS when IAM policy statements exist and none are admin-wildcard;
    N/A when there are no IAM policy statements in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "IAM-ELP/no-admin-wildcard"


@register_evaluator("KSI-IAM-ELP")
def evaluate(ctx: EvalContext) -> list[Finding]:
    statements = [
        s for s in ctx.graph.iam_statements if s.resource.provider in ctx.providers_in_scope
    ]
    if not statements:
        return []  # no IAM policy statements ⇒ N/A

    findings: list[Finding] = []
    for s in statements:
        if s.effect.lower() == "allow" and s.is_wildcard_action and s.is_wildcard_resource:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.ANTI_PATTERN_ABSENT,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=s.address,
                    source=s.resource.source,
                    message=(
                        f"{s.address}: Allow statement grants wildcard action on wildcard "
                        f'resource (Action:"*", Resource:"*") — administrator privilege.'
                    ),
                    remediation=(
                        "Scope IAM policy statements to the specific actions and resource ARNs "
                        "required; never grant Action:'*' on Resource:'*'."
                    ),
                )
            )

    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.ANTI_PATTERN_ABSENT,
                status=Status.PASS,
                message=(
                    f"None of {len(statements)} IAM policy statement(s) grant admin wildcard "
                    "(Action:'*' on Resource:'*')."
                ),
            )
        )
    return findings
