"""KSI-IAM-SNU — Securing Non-User Authentication (enforce).

Statement (2026.06.24.01): non-user (machine/service) accounts use secure,
short-lived authentication rather than long-lived static credentials.

The IaC-provable anti-pattern is a long-lived static IAM access key
(``aws_iam_access_key``). Workloads should use IAM roles / instance profiles /
workload identity, not static keys checked into infrastructure.

  - anti_pattern_absent: no static IAM access keys are declared.
  - PASS when IAM resources exist without static keys; N/A when there are no
    IAM resources in scope at all.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "IAM-SNU/no-static-access-keys"
_STATIC_KEY_TYPES = {"aws_iam_access_key"}


@register_evaluator("KSI-IAM-SNU")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    iam_resources = [r for r in scoped if r.type.startswith("aws_iam")]
    if not iam_resources:
        return []  # no IAM resources ⇒ N/A

    keys = [r for r in iam_resources if r.type in _STATIC_KEY_TYPES]
    if keys:
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.ANTI_PATTERN_ABSENT,
                status=Status.FAIL,
                severity=Severity.HIGH,
                resource_address=k.address,
                source=k.source,
                message=(
                    f"{k.address}: a long-lived static IAM access key is declared. "
                    "Use IAM roles / instance profiles / workload identity instead."
                ),
                remediation=(
                    "Remove aws_iam_access_key resources; grant workloads IAM roles "
                    "(instance profiles, IRSA, or OIDC federation) for short-lived credentials."
                ),
            )
            for k in keys
        ]

    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.ANTI_PATTERN_ABSENT,
            status=Status.PASS,
            message=(f"{len(iam_resources)} IAM resource(s) declared with no static access keys."),
        )
    ]
