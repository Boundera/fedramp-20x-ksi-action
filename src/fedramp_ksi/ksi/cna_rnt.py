"""KSI-CNA-RNT — Restricting Network Traffic (enforce).

Statement (2026.06.24.01): "Machine-based information resources are persistently
reviewed to ensure they are appropriately configured to limit inbound and
outbound network traffic."

Composed of two checks:
  - anti_pattern_absent: no sensitive/admin port is open to the world (0.0.0.0/0).
  - configured_correctly: egress is not unrestricted to the world.

Emits a PASS finding when in-scope network rules exist and are compliant, so the
enforce KSI can prove PASS; emits nothing (⇒ N/A) when there are no network rules.
"""

from __future__ import annotations

from ..checks.network import (
    unrestricted_egress_entries,
    world_open_sensitive_ports,
)
from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK_ANTI = "CNA-RNT/no-world-open-admin-ports"
CHECK_EGRESS = "CNA-RNT/egress-restricted"


@register_evaluator("KSI-CNA-RNT")
def evaluate(ctx: EvalContext) -> list[Finding]:
    rules = [r for r in ctx.graph.network_rules if r.resource.provider in ctx.providers_in_scope]
    if not rules:
        return []  # no in-scope network resources ⇒ N/A

    findings: list[Finding] = []
    anti_violations = 0
    egress_violations = 0

    for rule in rules:
        # anti_pattern_absent: sensitive ports open to the world.
        for entry in rule.ingress:
            for port, label in world_open_sensitive_ports(entry):
                anti_violations += 1
                findings.append(
                    ctx.finding(
                        check_id=CHECK_ANTI,
                        check_class=CheckClass.ANTI_PATTERN_ABSENT,
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_address=rule.address,
                        source=rule.source,
                        message=(
                            f"{rule.address}: port {port} ({label}) is open to the internet "
                            f"({', '.join(c for c in entry.cidrs)})."
                        ),
                        remediation=(
                            f"Restrict ingress on port {port} to specific trusted CIDRs or a "
                            "bastion/VPN; do not expose administrative ports to 0.0.0.0/0."
                        ),
                        details={"port": port, "service": label, "cidrs": list(entry.cidrs)},
                    )
                )

        # configured_correctly: egress must be restricted (no allow-all to world).
        for entry in unrestricted_egress_entries(rule):
            egress_violations += 1
            findings.append(
                ctx.finding(
                    check_id=CHECK_EGRESS,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=rule.address,
                    source=rule.source,
                    message=(
                        f"{rule.address}: unrestricted egress to the internet on "
                        f"protocol {entry.protocol}."
                    ),
                    remediation=(
                        "Limit outbound traffic to required destinations; avoid 0.0.0.0/0 egress."
                    ),
                    details={"protocol": entry.protocol, "cidrs": list(entry.cidrs)},
                )
            )

    if anti_violations == 0 and egress_violations == 0:
        findings.append(
            ctx.finding(
                check_id="CNA-RNT/compliant",
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                resource_address="",
                message=(
                    f"All {len(rules)} in-scope network rule group(s) limit inbound and "
                    "outbound traffic: no admin ports exposed to the internet, no unrestricted egress."
                ),
            )
        )
    return findings
