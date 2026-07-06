"""KSI-SVC-SIN — Securing Information (enforce, configured_correctly).

Statement (2026.06.24.01): information is secured at rest and in transit using
strong encryption.

The IaC-provable portion is encryption-at-rest on data-bearing resources.

  - configured_correctly: every in-scope data resource enables at-rest encryption.
  - A resource whose encryption flag is unknown-after-apply is skipped (no false
    PASS/FAIL). PASS when ≥1 resource proves encryption and none are unencrypted;
    N/A when there are no encryption-relevant resources in scope.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Severity, Status
from ..registry import register_evaluator

CHECK = "SVC-SIN/encryption-at-rest"


@register_evaluator("KSI-SVC-SIN")
def evaluate(ctx: EvalContext) -> list[Finding]:
    settings = [
        s for s in ctx.graph.encryption_settings if s.resource.provider in ctx.providers_in_scope
    ]
    # Only resources whose encryption state is *known* count toward scope.
    known = [s for s in settings if s.at_rest_enabled is not None]
    if not known:
        return []  # nothing provable ⇒ N/A

    findings: list[Finding] = []
    for s in known:
        if s.at_rest_enabled is False:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_address=s.address,
                    source=s.resource.source,
                    message=f"{s.address}: encryption at rest is disabled.",
                    remediation="Enable at-rest encryption (set encrypted/storage_encrypted = true; "
                    "prefer a customer-managed KMS key).",
                )
            )

    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(known)} in-scope data resource(s) enable encryption at rest.",
            )
        )
    return findings
