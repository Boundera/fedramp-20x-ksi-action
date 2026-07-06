"""KSI-SVC-ASM — Automating Secret Management (enforce).

Statement (2026.06.24.01): secrets are managed and automated (stored in a secret
manager, rotated), not hardcoded.

The clearest IaC-provable anti-pattern is a hardcoded plaintext credential: a
sensitive attribute (db password, secret string) present in the resolved plan as
a known literal rather than a reference/unknown-after-apply value.

  - anti_pattern_absent: no hardcoded plaintext credentials.
  - PASS when credential-bearing / secret-store resources exist with no hardcoded
    secret; N/A when none are in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "SVC-ASM/no-hardcoded-secrets"

# resource type -> sensitive attribute that must not be a plaintext literal
_SENSITIVE_ATTRS = {
    "aws_db_instance": "password",
    "aws_rds_cluster": "master_password",
    "aws_redshift_cluster": "master_password",
    "aws_secretsmanager_secret_version": "secret_string",
    "azurerm_key_vault_secret": "value",
    "google_sql_user": "password",
}
_SECRET_STORES = {"aws_secretsmanager_secret", "azurerm_key_vault", "google_secret_manager_secret"}


def _is_hardcoded(res, attr: str) -> bool:
    if res.is_unknown(attr):
        return False  # sourced from a secret manager / computed ⇒ not hardcoded
    val = res.get(attr)
    return isinstance(val, str) and val.strip() != ""


@register_evaluator("KSI-SVC-ASM")
def evaluate(ctx: EvalContext) -> list[Finding]:
    scoped = [r for r in ctx.graph.resources if r.provider in ctx.providers_in_scope]
    credential_resources = [r for r in scoped if r.type in _SENSITIVE_ATTRS]
    secret_stores = [r for r in scoped if r.type in _SECRET_STORES]
    if not credential_resources and not secret_stores:
        return []  # N/A

    findings: list[Finding] = []
    for r in credential_resources:
        if _is_hardcoded(r, _SENSITIVE_ATTRS[r.type]):
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.ANTI_PATTERN_ABSENT,
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: a plaintext credential is hardcoded in '{_SENSITIVE_ATTRS[r.type]}'.",
                    remediation="Store the secret in a secret manager and reference it "
                    "(so the value is resolved at apply time, not committed to IaC).",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.ANTI_PATTERN_ABSENT,
                status=Status.PASS,
                message="No hardcoded plaintext credentials; secrets are referenced or stored in a manager.",
            )
        )
    return findings
