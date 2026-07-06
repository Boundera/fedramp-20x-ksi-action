"""KSI-SVC-VRI — Validating Resource Integrity (advisory, control_declared).

Integrity/signing config (image signing, ECR scanning) is declared; runtime
signature verification is out of band — PARTIAL if declared.
"""

from __future__ import annotations

from ..checks.control import partial_if_present
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator

_TYPES = {
    "aws_signer_signing_profile",
    "aws_ecr_repository",
    "aws_ecr_registry_scanning_configuration",
}


@register_evaluator("KSI-SVC-VRI")
def evaluate(ctx: EvalContext) -> list[Finding]:
    return partial_if_present(
        ctx,
        _TYPES,
        check_id="SVC-VRI/integrity-declared",
        declared_msg="Resource-integrity config (signing/scanning) is declared; runtime verification is out of band.",
    )
