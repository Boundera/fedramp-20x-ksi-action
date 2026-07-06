"""KSI-SVC-ACM — Automating Configuration Management (enforce, control_declared).

Configuration is managed as code with drift detection. Evaluating a Terraform
plan already proves config-as-code; the additional IaC-provable control is
runtime drift detection — an AWS Config rule or SSM association.

  - control_declared: a Config rule / SSM association is declared when resources
    are managed.
  - FAIL when resources are managed but no drift-detection control is declared;
    N/A when there are no in-scope resources.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "SVC-ACM/drift-detection-declared"


@register_evaluator("KSI-SVC-ACM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    if not scoped:
        return []
    config_rules = [
        d
        for d in ctx.graph.detective_controls
        if d.kind == "config_rule" and d.resource.provider in ctx.providers_in_scope
    ]
    ssm = [r for r in scoped if r.type == "aws_ssm_association"]
    if config_rules or ssm:
        addr = config_rules[0].address if config_rules else ssm[0].address
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                resource_address=addr,
                message=f"Config-as-code with drift detection declared: {addr}.",
            )
        ]
    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.LOW,
            message=f"{len(scoped)} resource(s) managed but no drift-detection control "
            "(AWS Config rule or SSM association) is declared.",
            remediation="Declare an aws_config_config_rule or aws_ssm_association to detect and "
            "remediate configuration drift.",
        )
    ]
