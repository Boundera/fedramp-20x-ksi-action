"""KSI-CNA-MAT — Minimizing Attack Surface (enforce, anti_pattern_absent).

Statement (2026.06.24.01): the attack surface is minimized.

Broader than CNA-RNT: any ingress open to the internet on a port outside the
small set of expected public web ports (80/443) is unnecessary public exposure.

  - anti_pattern_absent: no world-open ingress on a non-web port.
  - PASS when network rules exist and none over-expose; N/A when none in scope.
"""

from __future__ import annotations

from ..checks.network import is_world_open
from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-MAT/no-unnecessary-public-exposure"
_PUBLIC_WEB_PORTS = {80, 443}


def _exposes_non_web(entry) -> bool:
    if entry.action != "allow" or entry.direction != "ingress" or not is_world_open(entry):
        return False
    # An all-ports rule (no range) to the world is always over-exposure.
    if entry.from_port is None or entry.to_port is None:
        return True
    # If the port range covers anything outside {80, 443}, it over-exposes.
    return any(
        port not in _PUBLIC_WEB_PORTS for port in range(entry.from_port, entry.to_port + 1)
    )


@register_evaluator("KSI-CNA-MAT")
def evaluate(ctx: EvalContext) -> list[Finding]:
    rules = [r for r in ctx.graph.network_rules if r.resource.provider in ctx.providers_in_scope]
    if not rules:
        return []

    findings: list[Finding] = []
    for rule in rules:
        for entry in rule.ingress:
            if _exposes_non_web(entry):
                span = (
                    "all ports"
                    if entry.from_port is None
                    else f"ports {entry.from_port}-{entry.to_port}"
                )
                findings.append(
                    ctx.finding(
                        check_id=CHECK,
                        check_class=CheckClass.ANTI_PATTERN_ABSENT,
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_address=rule.address,
                        source=rule.source,
                        message=f"{rule.address}: {span} open to the internet — unnecessary attack surface.",
                        remediation="Expose only required public web ports (80/443) to 0.0.0.0/0; "
                        "restrict everything else to trusted networks.",
                    )
                )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.ANTI_PATTERN_ABSENT,
                status=Status.PASS,
                message=f"No unnecessary public exposure across {len(rules)} network rule group(s).",
            )
        )
    return findings
