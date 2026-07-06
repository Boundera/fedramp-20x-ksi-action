"""KSI-SVC-VCM — Validating Communications (advisory@B → enforce@C).

Communications are encrypted/authenticated in transit. The IaC-provable signal
is that load-balancer listeners use TLS rather than plaintext HTTP.

  - configured_correctly: no aws_lb_listener serves plaintext HTTP (without a
    redirect to HTTPS).
  - PASS when listeners use HTTPS/TLS; FAIL on plaintext HTTP; N/A when no
    listeners in scope. (Gate-blocking only at class C.)
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Resource, Severity, Status
from ..registry import register_evaluator

CHECK = "SVC-VCM/tls-listeners"


def _is_plaintext_http(res: Resource) -> bool:
    if str(res.get("protocol", "")).upper() != "HTTP":
        return False
    # An HTTP listener whose default action redirects to HTTPS is acceptable.
    actions = res.get("default_action") or []
    for a in actions if isinstance(actions, list) else [actions]:
        if isinstance(a, dict) and a.get("type") == "redirect":
            redirect = a.get("redirect") or [{}]
            block = redirect[0] if isinstance(redirect, list) and redirect else redirect
            if isinstance(block, dict) and str(block.get("protocol", "")).upper() == "HTTPS":
                return False
    return True


@register_evaluator("KSI-SVC-VCM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    listeners = [
        r
        for r in ctx.graph.resources
        if r.type == "aws_lb_listener" and r.provider in ctx.providers_in_scope
    ]
    if not listeners:
        return []
    findings: list[Finding] = []
    for r in listeners:
        if _is_plaintext_http(r):
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: listener serves plaintext HTTP without redirect to HTTPS.",
                    remediation="Use an HTTPS/TLS listener (or redirect HTTP→HTTPS) so communications are encrypted.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(listeners)} load-balancer listener(s) use TLS (or redirect to HTTPS).",
            )
        )
    return findings
