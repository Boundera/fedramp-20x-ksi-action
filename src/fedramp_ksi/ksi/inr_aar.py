"""KSI-INR-AAR — Generating After-Action Reports (advisory, control_declared).

Incident detection infrastructure (GuardDuty / Security Hub) supports AAR
generation but the reports themselves are a process artifact — PARTIAL if
detection is declared, else N/A.
"""

from __future__ import annotations

from ..checks.control import detective_controls, partial_if_declared
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator


@register_evaluator("KSI-INR-AAR")
def evaluate(ctx: EvalContext) -> list[Finding]:
    controls = detective_controls(ctx, "guardduty", "security_hub")
    return partial_if_declared(
        ctx,
        controls,
        check_id="INR-AAR/detection-infra-declared",
        declared_msg="Incident-detection infrastructure is declared; after-action reports are process evidence.",
    )
