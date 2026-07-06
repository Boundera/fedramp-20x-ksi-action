"""The run-level findings model that every reporter consumes.

Reporters (SARIF, evidence pack, SDR, Check Run, PR comment, step summary) are
pure functions of :class:`RunReport`, so they are snapshot-testable and
deterministic (SPEC §4). Timestamps are held in a single ``generated_at`` field
that determinism tests strip.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..engine.engine import EngineResult
from ..model import AuthClass, Finding, KSIResult, Severity, Status


@dataclass(frozen=True)
class RunMeta:
    """GitHub / run context recorded in artifacts."""

    repository: str = "unknown/unknown"
    commit_sha: str = "0" * 40
    trigger_event: str = "unknown"
    actor: str = "unknown"
    run_url: str = ""
    action_version: str = "0.0.0"
    generated_at: str = ""  # ISO-8601; excluded from determinism hashing


@dataclass(frozen=True)
class RunReport:
    """Everything the reporters need, derived from an EngineResult + metadata."""

    results: tuple[KSIResult, ...]
    target_class: AuthClass
    ruleset_version: str
    ruleset_sha256: str
    ruleset_source_file: str
    gate_status: Status
    advisory_status: Status
    enforced_failures: int
    meta: RunMeta = field(default_factory=RunMeta)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def live_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if not f.suppressed]

    def findings_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.live_findings:
            if f.status in (Status.FAIL, Status.ERROR):
                counts[f.severity.value] += 1
        return counts

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if f.suppressed]


def build_report(
    engine_result: EngineResult,
    meta: RunMeta | None = None,
) -> RunReport:
    rs = engine_result.ruleset
    return RunReport(
        results=tuple(engine_result.results),
        target_class=engine_result.target_class,
        ruleset_version=rs.version,
        ruleset_sha256=rs.sha256,
        ruleset_source_file=rs.source_file,
        gate_status=engine_result.gate_status,
        advisory_status=engine_result.advisory_status,
        enforced_failures=engine_result.enforced_failures,
        meta=meta or RunMeta(),
    )
