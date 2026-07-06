"""Core enumerations for the FedRAMP 20x KSI engine.

These encode the honest-status model (SPEC §6), the three check classes
(SPEC §5), KSI dispositions (SPEC §7), severities (SPEC §10) and FedRAMP
20x authorization classes (A/B/C).
"""

from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    """Evaluation status for a check, KSI, or run (SPEC §6).

    Ordering (worst-first for gate semantics) is provided by ``severity_rank``.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NA = "N/A"
    MANUAL = "MANUAL"
    ERROR = "ERROR"

    @property
    def is_blocking(self) -> bool:
        """True for statuses that can block a gate (FAIL / ERROR)."""
        return self in (Status.FAIL, Status.ERROR)


# Worst-status precedence for rolling individual findings/checks up into a
# single KSI or run status. Higher number = worse. ``MANUAL`` and ``N/A`` are
# informational and never override a real PASS/FAIL within an enforce roll-up.
_STATUS_RANK: dict[Status, int] = {
    Status.NA: 0,
    Status.MANUAL: 1,
    Status.PASS: 2,
    Status.PARTIAL: 3,
    Status.FAIL: 4,
    Status.ERROR: 5,
}


def status_rank(status: Status) -> int:
    """Return the worst-status precedence rank for ``status``."""
    return _STATUS_RANK[status]


def worst_status(statuses: list[Status], default: Status = Status.NA) -> Status:
    """Return the worst status in ``statuses`` (highest precedence rank)."""
    if not statuses:
        return default
    return max(statuses, key=status_rank)


class CheckClass(str, Enum):
    """The three first-class check classes (SPEC §5).

    Not just "is the resource configured" — governing controls and
    anti-pattern absence are first-class.
    """

    CONFIGURED_CORRECTLY = "configured_correctly"
    CONTROL_DECLARED = "control_declared"
    ANTI_PATTERN_ABSENT = "anti_pattern_absent"


class Disposition(str, Enum):
    """How a KSI participates in the gate (SPEC §7).

    - ``ENFORCE``  — can block the build (PASS/FAIL).
    - ``ADVISORY`` — warn / PARTIAL; capability declared, outcome runtime.
    - ``MANUAL``   — no IaC control; recorded as MANUAL with an evidence pointer.
    """

    ENFORCE = "enforce"
    ADVISORY = "advisory"
    MANUAL = "manual"


class Severity(str, Enum):
    """Finding severity (SPEC §10)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def severity_rank(severity: Severity) -> int:
    """Return the ordering rank for ``severity`` (higher = worse)."""
    return _SEVERITY_RANK[severity]


class AuthClass(str, Enum):
    """FedRAMP 20x authorization class (SPEC §2 ``target_class``)."""

    A = "A"
    B = "B"
    C = "C"


class ClassRequirement(str, Enum):
    """Whether a KSI is required, optional, or N/A for a given class."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    NOT_APPLICABLE = "n/a"


class Provider(str, Enum):
    """Supported cloud providers (SPEC §16 — AWS/Azure/GCP for v1)."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
