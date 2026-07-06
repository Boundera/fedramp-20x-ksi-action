"""Status disposition policy — the honest-status hard-rules (SPEC §6).

Encodes which statuses each disposition may emit and how per-check findings
roll up into a single KSI status. Violations of the policy raise
:class:`StatusPolicyError`, which the engine converts into an ``ERROR`` status
for that KSI (a tooling failure is never silently a PASS).
"""

from __future__ import annotations

from ..model import Disposition, Status, worst_status
from ..model.findings import Finding


class StatusPolicyError(ValueError):
    """Raised when a finding violates the disposition status policy."""


# Allowed per-finding statuses by disposition (SPEC §6 table).
_ALLOWED: dict[Disposition, frozenset[Status]] = {
    Disposition.ENFORCE: frozenset({Status.PASS, Status.FAIL, Status.NA, Status.ERROR}),
    Disposition.ADVISORY: frozenset(
        {Status.PASS, Status.FAIL, Status.PARTIAL, Status.NA, Status.ERROR}
    ),
    Disposition.MANUAL: frozenset({Status.MANUAL, Status.NA}),
}


def allowed_statuses(disposition: Disposition) -> frozenset[Status]:
    return _ALLOWED[disposition]


def validate_findings(disposition: Disposition, findings: list[Finding]) -> None:
    """Raise StatusPolicyError if any finding emits a disallowed status.

    Hard rules (SPEC §6):
      - An enforce KSI may not emit PARTIAL (capability-only is advisory).
      - A manual KSI may only emit MANUAL / N/A — never PASS / FAIL.
    """
    allowed = _ALLOWED[disposition]
    for f in findings:
        if f.status not in allowed:
            raise StatusPolicyError(
                f"{f.ksi_id} ({disposition.value}) emitted disallowed status "
                f"{f.status.value} for check {f.check_id}; allowed={sorted(s.value for s in allowed)}"
            )


def rollup_status(findings: list[Finding]) -> Status:
    """Roll per-finding statuses into one KSI status.

    Only *live* (non-suppressed) findings affect the roll-up; a finding
    downgraded by a waiver or baseline no longer contributes its FAIL.
    Empty / all-suppressed ⇒ N/A (no in-scope resources ⇒ N/A, never FAIL).
    """
    live = [f.status for f in findings if not f.suppressed]
    return worst_status(live, default=Status.NA)
