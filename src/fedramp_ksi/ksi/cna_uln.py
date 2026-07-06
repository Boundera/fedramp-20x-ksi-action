"""KSI-CNA-ULN — Using Logical Networking (enforce, configured_correctly).

Logical isolation means data/compute resources live inside the private network
boundary, not exposed directly to the internet. The IaC-provable signal is the
``publicly_accessible`` / public-IP flags.

  - configured_correctly: no managed data/compute resource is publicly accessible.
  - FAIL when a resource sets publicly_accessible/associate_public_ip = true;
    N/A when no such resources are in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "CNA-ULN/no-public-data-tier"
# resource type -> attribute that must not be true (public exposure). The
# evaluator is provider-agnostic; adding a cloud is a table entry, not new logic.
_PUBLIC_FLAGS = {
    # AWS
    "aws_db_instance": "publicly_accessible",
    "aws_rds_cluster_instance": "publicly_accessible",
    "aws_redshift_cluster": "publicly_accessible",
    "aws_instance": "associate_public_ip_address",
    "aws_dms_replication_instance": "publicly_accessible",
    # Azure — data-tier servers must keep public network access disabled
    "azurerm_mssql_server": "public_network_access_enabled",
    "azurerm_postgresql_flexible_server": "public_network_access_enabled",
    "azurerm_mysql_flexible_server": "public_network_access_enabled",
}


@register_evaluator("KSI-CNA-ULN")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [
        r
        for r in ctx.graph.resources
        if r.type in _PUBLIC_FLAGS and r.provider in ctx.providers_in_scope
    ]
    known = [r for r in scoped if not r.is_unknown(_PUBLIC_FLAGS[r.type])]
    if not known:
        return []

    findings: list[Finding] = []
    for r in known:
        if bool(r.get(_PUBLIC_FLAGS[r.type])):
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: {_PUBLIC_FLAGS[r.type]} = true — resource is exposed outside the private network.",
                    remediation="Place the resource in private subnets and set publicly_accessible / "
                    "associate_public_ip_address = false.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(known)} data/compute resource(s) are kept within the private network.",
            )
        )
    return findings
