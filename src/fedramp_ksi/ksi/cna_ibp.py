"""KSI-CNA-IBP — Implementing Best Practices (enforce, configured_correctly).

Resources follow a security best-practice pack (CIS-style). The representative
IaC-provable control is S3 account/bucket public-access blocking: every declared
aws_s3_bucket_public_access_block must set all four protections true.

  - configured_correctly: public-access blocks fully enabled.
  - FAIL when any protection is false; N/A when no public-access blocks in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-IBP/s3-public-access-block"
_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


@register_evaluator("KSI-CNA-IBP")
def evaluate(ctx: EvalContext) -> list[Finding]:
    blocks = [
        r
        for r in ctx.graph.resources
        if r.type == "aws_s3_bucket_public_access_block" and r.provider in ctx.providers_in_scope
    ]
    if not blocks:
        return []

    findings: list[Finding] = []
    for r in blocks:
        disabled = [f for f in _FLAGS if r.get(f) is False]
        if disabled:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: S3 public-access protections disabled: {', '.join(disabled)}.",
                    remediation="Set all four public-access-block protections to true.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(blocks)} S3 public-access block(s) fully enabled.",
            )
        )
    return findings
