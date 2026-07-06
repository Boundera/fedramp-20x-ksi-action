"""KSI-CMT-VTD — Validating Throughout Deployment (advisory, control_declared).

Patch/validation infrastructure (SSM patch baseline / associations) is declared;
the deployment-time validation itself is pipeline/runtime — PARTIAL if declared.
"""

from __future__ import annotations

from ..checks.control import partial_if_present
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator

_TYPES = {"aws_ssm_patch_baseline", "aws_ssm_association", "aws_ssm_maintenance_window"}


@register_evaluator("KSI-CMT-VTD")
def evaluate(ctx: EvalContext) -> list[Finding]:
    return partial_if_present(
        ctx,
        _TYPES,
        check_id="CMT-VTD/patch-validation-declared",
        declared_msg="Patch/validation infrastructure (SSM) is declared; deployment validation runs in the pipeline.",
    )
