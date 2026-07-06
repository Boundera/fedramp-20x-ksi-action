"""KSI-MLA-OSM — Operating Security Monitoring (enforce, configured_correctly).

Central, tamper-resistant logging. The IaC-provable signal is CloudTrail log
file validation (integrity/tamper-evidence).

  - configured_correctly: declared CloudTrails enable log file validation.
  - FAIL if a trail exists without log file validation; N/A when no trail exists.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "MLA-OSM/log-file-validation"


@register_evaluator("KSI-MLA-OSM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    trails = [
        s
        for s in ctx.graph.logging_sinks
        if s.resource.type == "aws_cloudtrail" and s.resource.provider in ctx.providers_in_scope
    ]
    if not trails:
        return []  # N/A

    findings: list[Finding] = []
    for t in trails:
        if not t.immutable:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=t.address,
                    source=t.resource.source,
                    message=f"{t.address}: CloudTrail log file validation is disabled; logs are not tamper-evident.",
                    remediation="Set enable_log_file_validation = true so log integrity can be verified.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                resource_address=trails[0].address,
                message=f"All {len(trails)} CloudTrail(s) enable log file validation (tamper-evident).",
            )
        )
    return findings
