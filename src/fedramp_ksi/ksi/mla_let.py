"""KSI-MLA-LET — Logging Event Types (enforce, configured_correctly).

Audit logging must capture the right event types. The IaC-provable signal is a
CloudTrail configured as a multi-region trail (so management events across all
regions are captured), including management events.

  - configured_correctly: a declared CloudTrail is multi-region + logs management
    events. FAIL if a trail exists but is single-region / management events off.
  - N/A when no CloudTrail is declared (nothing to evaluate).
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, LoggingSink, Severity, Status
from ..registry import register_evaluator

CHECK = "MLA-LET/multi-region-management-events"


def _trails(ctx: EvalContext) -> list[LoggingSink]:
    return [
        s
        for s in ctx.graph.logging_sinks
        if s.resource.type == "aws_cloudtrail" and s.resource.provider in ctx.providers_in_scope
    ]


@register_evaluator("KSI-MLA-LET")
def evaluate(ctx: EvalContext) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return []  # no trail ⇒ N/A

    findings: list[Finding] = []
    for t in trails:
        multi_region = bool(t.resource.get("is_multi_region_trail"))
        # include_management_events defaults to true when unset in AWS.
        mgmt = t.resource.get("include_management_events")
        mgmt_on = True if mgmt is None else bool(mgmt)
        if not multi_region or not mgmt_on:
            reason = []
            if not multi_region:
                reason.append("not multi-region")
            if not mgmt_on:
                reason.append("management events disabled")
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=t.address,
                    source=t.resource.source,
                    message=f"{t.address}: CloudTrail {' and '.join(reason)}; event coverage is incomplete.",
                    remediation="Set is_multi_region_trail = true and include management events "
                    "so all regions/control-plane activity are captured.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                resource_address=trails[0].address,
                message=f"{len(trails)} CloudTrail(s) capture multi-region management events.",
            )
        )
    return findings
