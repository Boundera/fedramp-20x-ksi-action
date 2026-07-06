"""Evaluation context handed to each KSI evaluator."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import AuthClass, Finding, Provider, Severity, Status
from ..model.graph import ResourceGraph
from ..model.resources import SourceRef
from ..registry import RegistryEntry
from ..ruleset import KSIDefinition


@dataclass(frozen=True)
class EvalContext:
    """Everything an evaluator needs to run against the normalized graph."""

    graph: ResourceGraph
    target_class: AuthClass
    entry: RegistryEntry
    ksi_def: KSIDefinition
    providers_in_scope: tuple[Provider, ...]
    # GitHub trigger event (used by a couple of process-aware checks, e.g. MLA-EVC).
    trigger_event: str = "unknown"

    @property
    def ksi_id(self) -> str:
        return self.entry.ksi_id

    @property
    def default_severity(self) -> Severity:
        return self.entry.default_severity

    def finding(
        self,
        *,
        check_id: str,
        status: Status,
        message: str,
        resource_address: str = "",
        source: SourceRef | None = None,
        severity: Severity | None = None,
        remediation: str = "",
        check_class: object = None,
        details: dict | None = None,
    ) -> Finding:
        """Helper to build a Finding pre-filled with KSI/context metadata."""
        from ..model import CheckClass

        cc = (
            check_class
            if check_class is not None
            else (
                self.entry.check_classes[0]
                if self.entry.check_classes
                else CheckClass.CONFIGURED_CORRECTLY
            )
        )
        return Finding(
            ksi_id=self.ksi_id,
            check_id=check_id,
            check_class=cc,  # type: ignore[arg-type]
            severity=severity or self.default_severity,
            status=status,
            message=message,
            resource_address=resource_address,
            source=source or SourceRef(),
            remediation=remediation,
            details=details or {},
        )
