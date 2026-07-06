"""Finding and result types produced by checks and KSI evaluators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import CheckClass, Severity, Status
from .resources import SourceRef


@dataclass(frozen=True)
class Finding:
    """A single finding emitted by a check (SPEC §5).

    ``status`` is the per-finding outcome. A check yields zero or more
    findings; the KSI evaluator rolls them into a KSI status under the
    disposition policy.
    """

    ksi_id: str
    check_id: str
    check_class: CheckClass
    severity: Severity
    status: Status
    message: str
    resource_address: str = ""
    source: SourceRef = field(default_factory=SourceRef)
    remediation: str = ""
    # Set when a waiver suppressed this finding (records the waiver reference).
    waiver_ref: str | None = None
    # Set when a baseline entry suppressed this finding.
    baselined: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def suppressed(self) -> bool:
        return self.waiver_ref is not None or self.baselined

    def with_waiver(self, waiver_ref: str) -> Finding:
        return Finding(**{**self.__dict__, "waiver_ref": waiver_ref})

    def with_baseline(self) -> Finding:
        return Finding(**{**self.__dict__, "baselined": True})

    def as_dict(self) -> dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "check_id": self.check_id,
            "check_class": self.check_class.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "message": self.message,
            "resource_address": self.resource_address,
            "source": self.source.as_dict(),
            "remediation": self.remediation,
            "waiver_ref": self.waiver_ref,
            "baselined": self.baselined,
            "details": self.details,
        }


@dataclass(frozen=True)
class KSIResult:
    """The rolled-up evaluation result for one KSI."""

    ksi_id: str
    name: str
    disposition: str
    status: Status
    findings: tuple[Finding, ...] = ()
    # True when the KSI is in the enforce-set for the run's target class.
    enforced: bool = False
    notes: str = ""

    @property
    def live_findings(self) -> tuple[Finding, ...]:
        """Findings not suppressed by a waiver or baseline."""
        return tuple(f for f in self.findings if not f.suppressed)

    @property
    def fail_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.live_findings if f.status == Status.FAIL)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "name": self.name,
            "disposition": self.disposition,
            "status": self.status.value,
            "enforced": self.enforced,
            "notes": self.notes,
            "findings": [f.as_dict() for f in self.findings],
        }
