"""KSI-SCR-MIT — Mitigating Supply Chain Risk (enforce, configured_correctly).

Container registries scan images and use immutable tags. The IaC-provable
control is the ECR repository configuration.

  - configured_correctly: aws_ecr_repository enables scan_on_push and
    IMMUTABLE tags.
  - FAIL when scanning is off or tags are MUTABLE; N/A when no ECR repos.
"""

from __future__ import annotations

from ..engine.context import EvalContext
from ..model import CheckClass, Finding, Resource, Severity, Status
from ..registry import register_evaluator

CHECK = "SCR-MIT/ecr-scan-and-immutability"


def _scan_on_push(res: Resource) -> bool:
    cfg = res.get("image_scanning_configuration")
    if isinstance(cfg, list) and cfg:
        return bool(cfg[0].get("scan_on_push"))
    if isinstance(cfg, dict):
        return bool(cfg.get("scan_on_push"))
    return False


@register_evaluator("KSI-SCR-MIT")
def evaluate(ctx: EvalContext) -> list[Finding]:
    repos = [
        r
        for r in ctx.graph.resources
        if r.type == "aws_ecr_repository" and r.provider in ctx.providers_in_scope
    ]
    if not repos:
        return []

    findings: list[Finding] = []
    for r in repos:
        problems = []
        if not _scan_on_push(r):
            problems.append("scan_on_push disabled")
        if str(r.get("image_tag_mutability", "MUTABLE")).upper() != "IMMUTABLE":
            problems.append("tags are MUTABLE")
        if problems:
            findings.append(
                ctx.finding(
                    check_id=CHECK,
                    check_class=CheckClass.CONFIGURED_CORRECTLY,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_address=r.address,
                    source=r.source,
                    message=f"{r.address}: {', '.join(problems)}.",
                    remediation="Set image_tag_mutability = IMMUTABLE and enable scan_on_push.",
                )
            )
    if not findings:
        findings.append(
            ctx.finding(
                check_id=CHECK,
                check_class=CheckClass.CONFIGURED_CORRECTLY,
                status=Status.PASS,
                message=f"All {len(repos)} ECR repo(s) scan images and use immutable tags.",
            )
        )
    return findings
