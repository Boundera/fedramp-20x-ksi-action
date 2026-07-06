"""KSI-CNA-RVP — Reviewing Protections (advisory, control_declared).

Perimeter protections (WAF / Shield / Cloud Armor) are declared; their
effectiveness review is a runtime/process activity — PARTIAL if declared.
"""

from __future__ import annotations

from ..checks.control import partial_if_present
from ..engine.context import EvalContext
from ..model import Finding
from ..registry import register_evaluator

_TYPES = {
    "aws_wafv2_web_acl",
    "aws_waf_web_acl",
    "aws_shield_protection",
    "google_compute_security_policy",
    "azurerm_web_application_firewall_policy",
}


@register_evaluator("KSI-CNA-RVP")
def evaluate(ctx: EvalContext) -> list[Finding]:
    return partial_if_present(
        ctx,
        _TYPES,
        check_id="CNA-RVP/waf-declared",
        declared_msg="Perimeter protection (WAF/Shield/Armor) is declared; effectiveness review is runtime/process.",
    )
