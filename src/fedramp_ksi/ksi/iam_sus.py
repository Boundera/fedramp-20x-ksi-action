"""KSI-IAM-SUS — Responding to Suspicious Activity (advisory, control_declared).

Threat-detection infrastructure (GuardDuty) can be declared in IaC, but the
*response* is a runtime/process outcome — so this caps at PARTIAL when detection
is declared, N/A when it is absent.
"""

from __future__ import annotations

from ..checks.control import detective_controls, partial_if_declared
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator


@register_evaluator("KSI-IAM-SUS")
def evaluate(ctx: EvalContext) -> list[Finding]:
    controls = detective_controls(ctx, "guardduty")
    return partial_if_declared(
        ctx,
        controls,
        check_id="IAM-SUS/threat-detection-declared",
        declared_msg="Threat detection (GuardDuty) is declared; response validation is runtime/process.",
    )
