"""KSI-INR-RPI — Reviewing Past Incidents (advisory, control_declared).

Vulnerability/finding infrastructure (Inspector / Security Hub) supports
incident review; PARTIAL if declared, else N/A.
"""

from __future__ import annotations

from ..checks.control import detective_controls, partial_if_declared
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator


@register_evaluator("KSI-INR-RPI")
def evaluate(ctx: EvalContext) -> list[Finding]:
    controls = detective_controls(ctx, "inspector", "security_hub")
    return partial_if_declared(
        ctx,
        controls,
        check_id="INR-RPI/vuln-infra-declared",
        declared_msg="Vulnerability-finding infrastructure (Inspector) is declared; incident review is process.",
    )
