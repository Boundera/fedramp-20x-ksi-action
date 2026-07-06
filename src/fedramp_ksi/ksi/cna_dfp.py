"""KSI-CNA-DFP — Defining Functionality & Privileges (enforce, configured_correctly).

Least functionality: only the required protocols/ports are permitted. An ingress
rule that allows *all protocols* (protocol "-1"/all) is over-permissive.

  - configured_correctly: no ingress rule permits all protocols.
  - PASS when network rules exist and all specify protocols; N/A when none.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-DFP/no-all-protocols-ingress"


@register_evaluator("KSI-CNA-DFP")
def evaluate(ctx: EvalContext) -> list[Finding]:
    rules = [r for r in ctx.graph.network_rules if r.resource.provider in ctx.providers_in_scope]
    if not rules:
        return []

    findings: list[Finding] = []
    for rule in rules:
        for entry in rule.ingress:
            if entry.action == "allow" and entry.is_all_protocols:
                findings.append(
                    ctx.finding(
                        check_id=CHECK,
                        check_class=CheckClass.CONFIGURED_CORRECTLY,
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        resource_address=rule.address,
                        source=rule.source,
                        message=f"{rule.address}: an ingress rule permits ALL protocols — not least functionality.",
                        remediation="Specify the exact protocol(s) and port(s) required; do not use protocol '-1'/all.",
                    )
                )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All ingress rules across {len(rules)} group(s) specify explicit protocols.",
            )
        )
    return findings
