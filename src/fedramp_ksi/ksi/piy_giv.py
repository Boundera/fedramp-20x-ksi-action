"""KSI-PIY-GIV — Generating Inventories (enforce, control_declared).

An automated asset inventory. The IaC-provable control is an AWS Config
configuration recorder (records the resource inventory continuously).

  - control_declared: a config recorder is declared when resources are managed.
  - FAIL when resources are managed but no inventory control is declared; N/A
    when there are no in-scope resources.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "PIY-GIV/inventory-control-declared"


@register_evaluator("KSI-PIY-GIV")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    if not scoped:
        return []
    recorders = [
        d
        for d in ctx.graph.detective_controls
        if d.kind == "config_recorder" and d.resource.provider in ctx.providers_in_scope
    ]
    if recorders:
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                resource_address=recorders[0].address,
                message=f"Asset-inventory control declared: {recorders[0].address}.",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            message=f"{len(scoped)} resource(s) managed but no automated inventory (AWS Config recorder) is declared.",
            remediation="Declare an aws_config_configuration_recorder to continuously inventory resources.",
        )
    ]
