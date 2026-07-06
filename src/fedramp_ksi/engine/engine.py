"""KSI engine — runs in-scope KSI evaluators against the normalized graph.

For each requested KSI the engine:
  1. resolves the effective disposition for the run's target class,
  2. emits MANUAL directly for manual KSIs (never PASS/FAIL — SPEC §6),
  3. otherwise runs the registered evaluator, validates its findings against the
     status policy, applies waivers/baseline, and rolls up to a KSI status,
  4. converts any evaluator/tooling failure into ERROR (never a silent PASS).

The engine never edits per-KSI logic — adding a KSI is a registry entry + an
evaluator + fixtures (SPEC §1.8).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..model import (
    AuthClass,
    ClassRequirement,
    Disposition,
    Finding,
    KSIResult,
    Provider,
    Status,
)
from ..model.graph import ResourceGraph
from ..registry import RegistryEntry, all_entries, get_entry, get_evaluator
from ..ruleset import Ruleset, load_ruleset
from .context import EvalContext
from .status import StatusPolicyError, rollup_status, validate_findings

logger = logging.getLogger(__name__)

# Optional hook: a callable that suppresses/annotates findings (waivers, baseline).
FindingTransform = "callable"


@dataclass
class EngineResult:
    """The full result of an engine run."""

    results: list[KSIResult]
    target_class: AuthClass
    ruleset: Ruleset

    @property
    def enforced_failures(self) -> int:
        return sum(len(r.fail_findings) for r in self.results if r.enforced)

    @property
    def gate_status(self) -> Status:
        """Worst status across the enforce-set (the gate-blocking status)."""
        enforced = [r for r in self.results if r.enforced]
        if not enforced:
            return Status.NA
        return _worst([r.status for r in enforced])

    @property
    def advisory_status(self) -> Status:
        advisory = [r for r in self.results if not r.enforced and r.disposition != "manual"]
        if not advisory:
            return Status.NA
        return _worst([r.status for r in advisory])


def _worst(statuses: list[Status]) -> Status:
    from ..model import worst_status

    # For gate purposes, MANUAL/N/A never override a real PASS.
    real = [s for s in statuses if s not in (Status.MANUAL, Status.NA)]
    if real:
        return worst_status(real)
    return worst_status(statuses, default=Status.NA)


def _providers_in_scope(
    entry: RegistryEntry, requested: tuple[Provider, ...] | None, graph: ResourceGraph
) -> tuple[Provider, ...]:
    scope = set(entry.providers)
    if requested:
        scope &= set(requested)
    return tuple(p for p in entry.providers if p in scope)


class Engine:
    """Evaluates KSIs against a normalized resource graph."""

    def __init__(
        self,
        ruleset: Ruleset | None = None,
        finding_transforms: list | None = None,
    ) -> None:
        self.ruleset = ruleset or load_ruleset()
        self.finding_transforms = finding_transforms or []
        # Importing the KSI package registers all evaluators (idempotent).
        from ..ksi import load_all

        load_all()

    def evaluate(
        self,
        graph: ResourceGraph,
        *,
        target_class: AuthClass = AuthClass.C,
        ksi_ids: list[str] | None = None,
        providers: tuple[Provider, ...] | None = None,
        trigger_event: str = "unknown",
    ) -> EngineResult:
        entries = [get_entry(k) for k in ksi_ids] if ksi_ids else list(all_entries())
        results = [
            self._evaluate_one(e, graph, target_class, providers, trigger_event) for e in entries
        ]
        return EngineResult(results=results, target_class=target_class, ruleset=self.ruleset)

    def _evaluate_one(
        self,
        entry: RegistryEntry,
        graph: ResourceGraph,
        target_class: AuthClass,
        providers: tuple[Provider, ...] | None,
        trigger_event: str,
    ) -> KSIResult:
        ksi_def = self.ruleset.get(entry.ksi_id)
        disposition = entry.disposition_for(target_class)
        requirement = ksi_def.requirement_for(target_class)
        enforced = disposition is Disposition.ENFORCE

        # Manual KSIs: never PASS/FAIL. MANUAL, or N/A if out-of-class.
        if disposition is Disposition.MANUAL:
            status = Status.NA if requirement is ClassRequirement.NOT_APPLICABLE else Status.MANUAL
            return KSIResult(
                ksi_id=entry.ksi_id,
                name=ksi_def.name,
                disposition=disposition.value,
                status=status,
                enforced=False,
                notes=entry.notes or "manual — evidence is external",
            )

        evaluator = get_evaluator(entry.ksi_id)
        if evaluator is None:
            return KSIResult(
                ksi_id=entry.ksi_id,
                name=ksi_def.name,
                disposition=disposition.value,
                status=Status.NA,
                enforced=enforced,
                notes="evaluator not yet implemented",
            )

        scope = _providers_in_scope(entry, providers, graph)
        ctx = EvalContext(
            graph=graph,
            target_class=target_class,
            entry=entry,
            ksi_def=ksi_def,
            providers_in_scope=scope,
            trigger_event=trigger_event,
        )

        try:
            findings: list[Finding] = list(evaluator(ctx))
            validate_findings(disposition, findings)
            findings = self._apply_transforms(findings)
            status = rollup_status(findings)
        except StatusPolicyError as exc:
            logger.error("Status policy violation for %s: %s", entry.ksi_id, exc)
            return self._error_result(entry, ksi_def, disposition, enforced, str(exc))
        except Exception as exc:  # noqa: BLE001 — tooling failure ⇒ ERROR, never PASS
            logger.exception("Evaluator for %s crashed", entry.ksi_id)
            return self._error_result(entry, ksi_def, disposition, enforced, repr(exc))

        return KSIResult(
            ksi_id=entry.ksi_id,
            name=ksi_def.name,
            disposition=disposition.value,
            status=status,
            findings=tuple(findings),
            enforced=enforced,
            notes=entry.notes,
        )

    def _apply_transforms(self, findings: list[Finding]) -> list[Finding]:
        for transform in self.finding_transforms:
            findings = transform(findings)
        return findings

    @staticmethod
    def _error_result(
        entry: RegistryEntry,
        ksi_def,
        disposition: Disposition,
        enforced: bool,
        msg: str,
    ) -> KSIResult:
        from ..model import CheckClass, Severity

        err = Finding(
            ksi_id=entry.ksi_id,
            check_id=f"{entry.ksi_id}/engine",
            check_class=entry.check_classes[0]
            if entry.check_classes
            else CheckClass.CONFIGURED_CORRECTLY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            message=f"Evaluator error: {msg}",
        )
        return KSIResult(
            ksi_id=entry.ksi_id,
            name=ksi_def.name,
            disposition=disposition.value,
            status=Status.ERROR,
            findings=(err,),
            enforced=enforced,
            notes="tooling failure",
        )
