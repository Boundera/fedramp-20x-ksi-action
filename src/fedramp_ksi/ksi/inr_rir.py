"""KSI-INR-RIR — Reviewing Incident Response (advisory, control_declared).

Security Hub (findings aggregation) supports IR review; the review itself is a
process outcome — PARTIAL if declared, else N/A.
"""

from __future__ import annotations

from ..checks.control import detective_controls, partial_if_declared
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator


@register_evaluator("KSI-INR-RIR")
def evaluate(ctx: EvalContext) -> list[Finding]:
    controls = detective_controls(ctx, "security_hub", "guardduty")
    return partial_if_declared(
        ctx,
        controls,
        check_id="INR-RIR/findings-aggregation-declared",
        declared_msg="Findings aggregation (Security Hub) is declared; IR review is a process outcome.",
    )
