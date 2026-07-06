"""KSI-MLA-RVL — Reviewing Logs (advisory, control_declared).

Logging is enabled (CloudTrail / log groups); the log *review* is a runtime
activity — PARTIAL when logging is declared.
"""

from __future__ import annotations

from ..checks.control import partial_if_declared
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator


@register_evaluator("KSI-MLA-RVL")
def evaluate(ctx: EvalContext) -> list[Finding]:
    sinks = [s for s in ctx.graph.logging_sinks if s.resource.provider in ctx.providers_in_scope]
    return partial_if_declared(
        ctx,
        sinks,
        check_id="MLA-RVL/logging-declared",
        declared_msg="Logging is declared; log review is a runtime/process activity.",
    )
