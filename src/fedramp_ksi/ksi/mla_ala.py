"""KSI-MLA-ALA — Authorizing Log Access (advisory@B → enforce@C).

Access to logs is controlled. The IaC-provable signal is that log destinations
are encrypted with a KMS key (access is mediated by key policy).

  - configured_correctly: log sinks (CloudTrail / CloudWatch) set a KMS key.
  - PASS when all log sinks are KMS-encrypted; FAIL when a sink lacks KMS; N/A
    when no log sinks in scope. (Gate-blocking only at class C.)
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "MLA-ALA/log-store-kms"


@register_evaluator("KSI-MLA-ALA")
def evaluate(ctx: EvalContext) -> list[Finding]:
    sinks = [s for s in ctx.graph.logging_sinks if s.resource.provider in ctx.providers_in_scope]
    if not sinks:
        return []
    findings: list[Finding] = []
    for s in sinks:
        if not s.kms_key:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=s.address,
                    source=s.resource.source,
                    message=f"{s.address}: log destination is not KMS-encrypted — log access is not key-controlled.",
                    remediation="Set a kms_key_id on the log destination so access is mediated by the key policy.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(sinks)} log destination(s) are KMS-encrypted.",
            )
        )
    return findings
