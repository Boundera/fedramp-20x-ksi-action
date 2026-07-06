"""KSI-CNA-EIS — Enforcing Intended State (advisory@B → enforce@C).

An enforcement service continuously corrects drift toward the intended state:
AWS Config with remediation, or SSM associations.

  - control_declared: a Config rule / SSM association is declared.
  - PASS when declared; FAIL when resources are managed but none is declared;
    N/A when there are no in-scope resources. (Non-blocking at class A/B;
    gate-blocking at class C.)
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-EIS/enforcement-declared"


@register_evaluator("KSI-CNA-EIS")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    if not scoped:
        return []
    rules = [
        d
        for d in ctx.graph.detective_controls
        if d.kind == "config_rule" and d.resource.provider in ctx.providers_in_scope
    ]
    ssm = [
        r
        for r in scoped
        if r.type in ("aws_ssm_association", "aws_config_remediation_configuration")
    ]
    if rules or ssm:
        addr = rules[0].address if rules else ssm[0].address
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                resource_address=addr,
                message=f"Intended-state enforcement declared: {addr}.",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            message=f"{len(scoped)} resource(s) managed but no state-enforcement control "
            "(AWS Config rule / SSM) is declared.",
            remediation="Declare aws_config_config_rule (with remediation) or aws_ssm_association "
            "to continuously enforce intended state.",
        )
    ]
