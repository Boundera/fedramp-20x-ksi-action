"""KSI-CMT-LMC — Logging Management Changes (enforce, configured_correctly).

Changes to the system must be logged. The IaC-provable control is change-logging
infrastructure: a CloudTrail (control-plane API activity) or an AWS Config
recorder (configuration change history).

  - configured_correctly: change-logging infra is declared and enabled.
  - FAIL when the plan manages resources but declares neither; N/A when there are
    no in-scope resources.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Status
from ..registry import register_evaluator

CHECK = "CMT-LMC/change-logging-declared"


@register_evaluator("KSI-CMT-LMC")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    if not scoped:
        return []  # N/A

    trails = [
        s
        for s in ctx.graph.logging_sinks
        if s.resource.type == "aws_cloudtrail"
        and s.enabled
        and s.resource.provider in ctx.providers_in_scope
    ]
    recorders = [
        d
        for d in ctx.graph.detective_controls
        if d.kind == "config_recorder" and d.resource.provider in ctx.providers_in_scope
    ]
    if trails or recorders:
        addr = trails[0].address if trails else recorders[0].address
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                resource_address=addr,
                message=f"Change-logging infrastructure is declared: {addr}.",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONFIGURED_CORRECTLY,
            status=Status.FAIL,
            message=(
                f"The plan manages {len(scoped)} resource(s) but declares no change-logging "
                "infrastructure (CloudTrail or AWS Config recorder)."
            ),
            remediation="Declare an enabled aws_cloudtrail (management events) or an "
            "aws_config_configuration_recorder to log changes.",
        )
    ]
