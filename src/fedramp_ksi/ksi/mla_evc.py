"""KSI-MLA-EVC — Evaluating Configurations (enforce, control_declared).

Statement (2026.06.24.01): machine-based information resources are persistently
evaluated to ensure they are configured according to the approved configuration.

This action *is* one such persistent evaluation, but the IaC-declarable control
is a continuous configuration-evaluation service: an AWS Config configuration
recorder (or equivalent). The check asserts that governing control is declared
and enabled whenever the plan manages cloud resources.

  - control_declared: a config-recorder DetectiveControl is present + enabled.
  - PASS when declared; FAIL when the plan manages resources but declares none;
    N/A when there are no in-scope resources at all.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "MLA-EVC/config-evaluation-declared"
_RECORDER_KINDS = {"config_recorder"}


@register_evaluator("KSI-MLA-EVC")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    if not scoped:
        return []  # no in-scope resources ⇒ N/A

    recorders = [
        d
        for d in ctx.graph.detective_controls
        if d.kind in _RECORDER_KINDS and d.resource.provider in ctx.providers_in_scope
    ]
    active = [d for d in recorders if d.enabled]

    if active:
        return [
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONTROL_DECLARED,
                status=Status.PASS,
                resource_address=active[0].address,
                source=active[0].resource.source,
                message=(
                    f"Continuous configuration evaluation is declared: "
                    f"{active[0].address} ({active[0].kind})."
                ),
            )
        ]

    return [
        ctx.finding(
            check_id=CHECK,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            message=(
                f"The plan manages {len(scoped)} cloud resource(s) but declares no continuous "
                "configuration-evaluation control (e.g. aws_config_configuration_recorder)."
            ),
            remediation=(
                "Declare an AWS Config configuration recorder + delivery channel (or the Azure/GCP "
                "equivalent) so resource configuration is persistently evaluated."
            ),
        )
    ]
