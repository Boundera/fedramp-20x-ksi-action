"""KSI-SCR-MON — Monitoring Supply Chain Risk (advisory, control_declared).

Dependency/vulnerability scanning infrastructure (Inspector / ECR scanning) is
declared; ongoing monitoring outcome is runtime — PARTIAL if declared.
"""

from __future__ import annotations

from ..checks.control import partial_if_present
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator

_TYPES = {"aws_inspector2_enabler", "aws_ecr_repository", "aws_ecr_registry_scanning_configuration"}


@register_evaluator("KSI-SCR-MON")
def evaluate(ctx: EvalContext) -> list[Finding]:
    return partial_if_present(
        ctx,
        _TYPES,
        check_id="SCR-MON/scanning-declared",
        declared_msg="Dependency/vulnerability scanning (Inspector/ECR) is declared; monitoring outcome is runtime.",
    )
