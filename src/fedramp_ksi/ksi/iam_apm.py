"""KSI-IAM-APM — Adopting Passwordless / strong auth (enforce, configured_correctly).

A strong account password policy is the IaC-provable control.

  - configured_correctly: aws_iam_account_password_policy meets minimums
    (length >= 14; upper/lower/number/symbol required).
  - FAIL when a password policy is weak; N/A when none is declared.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "IAM-APM/strong-password-policy"
_REQUIRED_FLAGS = (
    "require_uppercase_characters",
    "require_lowercase_characters",
    "require_numbers",
    "require_symbols",
)
_MIN_LENGTH = 14


@register_evaluator("KSI-IAM-APM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    policies = [
        r
        for r in ctx.graph.resources
        if r.type == "aws_iam_account_password_policy" and r.provider in ctx.providers_in_scope
    ]
    if not policies:
        return []

    findings: list[Finding] = []
    for r in policies:
        weaknesses = []
        length = r.get("minimum_password_length")
        if isinstance(length, int) and length < _MIN_LENGTH:
            weaknesses.append(f"minimum_password_length={length} (<{_MIN_LENGTH})")
        for flag in _REQUIRED_FLAGS:
            if r.get(flag) is False:
                weaknesses.append(f"{flag}=false")
        if weaknesses:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: weak password policy — {', '.join(weaknesses)}.",
                    remediation=f"Require length >= {_MIN_LENGTH} and upper/lower/number/symbol complexity.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message="Account password policy meets complexity + length minimums.",
            )
        )
    return findings
