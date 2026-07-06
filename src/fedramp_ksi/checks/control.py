"""Advisory control-declared primitive (SPEC §5, §6).

Advisory KSIs assert that a governing control (detective service, guardrail) is
*declared*, but the runtime outcome can't be proven from a plan — so they cap at
``PARTIAL`` when the control is present and ``N/A`` when it is absent (never a
false ``PASS``). This helper builds that finding for the common case.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, DetectiveControl, Finding, Status


def detective_controls(ctx: EvalContext, *kinds: str) -> list[DetectiveControl]:
    wanted = set(kinds)
    return [
        d
        for d in ctx.graph.detective_controls
        if d.kind in wanted and d.enabled and d.resource.provider in ctx.providers_in_scope
    ]


def partial_if_declared(
    ctx: EvalContext,
    controls: list,
    *,
    check_id: str,
    declared_msg: str,
) -> list[Finding]:
    """PARTIAL when ≥1 control is declared, else N/A (empty)."""
    if not controls:
        return []  # capability not declared ⇒ N/A (can't prove)
    addr = getattr(controls[0], "address", "")
    return [
        ctx.finding(
            check_id=check_id,
            check_class=CheckClass.CONTROL_DECLARED,
            status=Status.PARTIAL,
            resource_address=addr,
            message=declared_msg,
        )
    ]
