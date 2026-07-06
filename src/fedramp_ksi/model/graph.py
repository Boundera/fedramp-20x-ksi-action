"""The normalized resource graph produced by the loader + provider adapters.

Evaluators query this graph (e.g. ``graph.network_rules``) rather than touching
provider-specific Terraform schemas. Adapters append normalized resources into
the typed collections; the generic ``resources`` list always holds every
resource for cross-cutting checks and inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .resources import (
    BackupConfig,
    DetectiveControl,
    EncryptionSetting,
    IamPolicyStatement,
    LoggingSink,
    NetworkRule,
    OrgGuardrail,
    Resource,
    SecretConfig,
)


@dataclass
class ResourceGraph:
    """Provider-agnostic, normalized view of a resolved Terraform plan."""

    resources: list[Resource] = field(default_factory=list)
    network_rules: list[NetworkRule] = field(default_factory=list)
    encryption_settings: list[EncryptionSetting] = field(default_factory=list)
    logging_sinks: list[LoggingSink] = field(default_factory=list)
    iam_statements: list[IamPolicyStatement] = field(default_factory=list)
    secrets: list[SecretConfig] = field(default_factory=list)
    backups: list[BackupConfig] = field(default_factory=list)
    detective_controls: list[DetectiveControl] = field(default_factory=list)
    org_guardrails: list[OrgGuardrail] = field(default_factory=list)
    # Provider names detected in the plan (e.g. {"aws"}).
    providers_detected: set[str] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not self.resources

    def resources_of_type(self, *types: str) -> list[Resource]:
        wanted = set(types)
        return [r for r in self.resources if r.type in wanted]

    def extend(self, other: ResourceGraph) -> None:
        self.resources.extend(other.resources)
        self.network_rules.extend(other.network_rules)
        self.encryption_settings.extend(other.encryption_settings)
        self.logging_sinks.extend(other.logging_sinks)
        self.iam_statements.extend(other.iam_statements)
        self.secrets.extend(other.secrets)
        self.backups.extend(other.backups)
        self.detective_controls.extend(other.detective_controls)
        self.org_guardrails.extend(other.org_guardrails)
        self.providers_detected |= other.providers_detected
