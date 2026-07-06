"""Gate / failure policy (SPEC §10).

Decides whether a run blocks the merge, from the ``fail_on`` policy and the
evaluated findings. Separated from the orchestrator so it is unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Severity, Status, severity_rank
from .reporters.report import RunReport


@dataclass(frozen=True)
class GateDecision:
    blocked: bool
    reason: str
    exit_code: int


def parse_fail_on(fail_on: str) -> tuple[str, Severity | None]:
    """Parse a ``fail_on`` input into (mode, threshold_severity)."""
    value = (fail_on or "enforce").strip().lower()
    if value in ("enforce", "none"):
        return value, None
    if value.startswith("severity:"):
        level = value.split(":", 1)[1].strip()
        try:
            return "severity", Severity(level)
        except ValueError as exc:
            raise ValueError(f"Invalid severity in fail_on={fail_on!r}") from exc
    raise ValueError(f"Unrecognized fail_on={fail_on!r}; use enforce|none|severity:<level>")


def decide(report: RunReport, fail_on: str = "enforce") -> GateDecision:
    """Return the gate decision for ``report`` under ``fail_on``."""
    mode, threshold = parse_fail_on(fail_on)

    if mode == "none":
        return GateDecision(False, "fail_on=none (report-only)", 0)

    # An engine/tooling ERROR in the enforce-set always blocks (never silent PASS).
    if report.gate_status == Status.ERROR:
        return GateDecision(True, "an enforced KSI errored during evaluation", 1)

    if mode == "enforce":
        if report.enforced_failures > 0:
            return GateDecision(True, f"{report.enforced_failures} unwaived enforced FAIL(s)", 1)
        return GateDecision(False, "no unwaived enforced failures", 0)

    # mode == "severity": block on any live FAIL at/above threshold, any class.
    assert threshold is not None
    over = [
        f
        for f in report.live_findings
        if f.status == Status.FAIL and severity_rank(f.severity) >= severity_rank(threshold)
    ]
    if over:
        return GateDecision(
            True, f"{len(over)} unwaived FAIL(s) at severity ≥ {threshold.value}", 1
        )
    return GateDecision(False, f"no unwaived failures at severity ≥ {threshold.value}", 0)
