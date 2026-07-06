"""Normalized, provider-agnostic resource model (SPEC §5).

Provider adapters translate concrete Terraform resource types into these
normalized types so KSI evaluators run against one abstraction rather than
provider-specific schemas. Every normalized resource carries file/line
provenance via :class:`SourceRef` so findings can point at the offending
declaration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import Provider


@dataclass(frozen=True)
class SourceRef:
    """File/line provenance for a resource or finding."""

    file: str = ""
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line}


@dataclass(frozen=True)
class Resource:
    """Generic normalized resource.

    Carries the resolved (post-plan) attributes for a single resource address,
    plus the originating provider and source location. ``attributes`` holds the
    resolved ``planned_values`` for the resource. ``unknown_keys`` lists
    attribute names that are unknown-after-apply (so evaluators can emit
    PARTIAL/N/A rather than a false PASS — SPEC §4).
    """

    address: str
    type: str
    provider: Provider
    name: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    source: SourceRef = field(default_factory=SourceRef)
    unknown_keys: tuple[str, ...] = ()
    mode: str = "managed"  # managed | data

    def get(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    def is_unknown(self, key: str) -> bool:
        return key in self.unknown_keys


# ---------------------------------------------------------------------------
# Specialized normalized types. Each is produced by provider adapters and
# consumed by check primitives. They intentionally hold only the fields the
# KSI evaluators need, plus a back-reference to the generic Resource.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkRuleEntry:
    """A single ingress/egress rule within a NetworkRule group."""

    direction: str  # "ingress" | "egress"
    protocol: str  # "tcp" | "udp" | "icmp" | "-1"/"all"
    from_port: int | None
    to_port: int | None
    cidrs: tuple[str, ...] = ()
    action: str = "allow"  # allow | deny (Azure NSG / GCP have explicit deny)

    def covers_port(self, port: int) -> bool:
        if self.from_port is None or self.to_port is None:
            # all-ports rule (protocol -1 or unspecified range)
            return True
        return self.from_port <= port <= self.to_port

    @property
    def is_all_protocols(self) -> bool:
        return self.protocol in ("-1", "all", "*", "")


@dataclass(frozen=True)
class NetworkRule:
    """Normalized firewall / security-group construct.

    Maps from aws_security_group, azurerm_network_security_rule/group,
    google_compute_firewall, etc.
    """

    resource: Resource
    ingress: tuple[NetworkRuleEntry, ...] = ()
    egress: tuple[NetworkRuleEntry, ...] = ()
    default_deny_egress: bool | None = None  # provider default semantics

    @property
    def address(self) -> str:
        return self.resource.address

    @property
    def source(self) -> SourceRef:
        return self.resource.source


@dataclass(frozen=True)
class EncryptionSetting:
    """Encryption-at-rest / in-transit setting for a data-bearing resource."""

    resource: Resource
    at_rest_enabled: bool | None
    kms_key: str | None = None
    in_transit_enforced: bool | None = None
    algorithm: str | None = None

    @property
    def address(self) -> str:
        return self.resource.address


@dataclass(frozen=True)
class LoggingSink:
    """A logging/audit destination (CloudTrail, diag settings, audit logs)."""

    resource: Resource
    enabled: bool | None
    kms_key: str | None = None
    retention_days: int | None = None
    immutable: bool | None = None  # object-lock / immutability

    @property
    def address(self) -> str:
        return self.resource.address


@dataclass(frozen=True)
class IamPolicyStatement:
    """A single normalized IAM policy statement."""

    resource: Resource
    effect: str  # Allow | Deny
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    principals: tuple[str, ...] = ()
    conditions: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return self.resource.address

    @property
    def is_wildcard_action(self) -> bool:
        return any(a in ("*", "*:*") for a in self.actions)

    @property
    def is_wildcard_resource(self) -> bool:
        return any(r == "*" for r in self.resources)


@dataclass(frozen=True)
class SecretConfig:
    """A secret store / managed credential configuration."""

    resource: Resource
    rotation_enabled: bool | None = None
    rotation_days: int | None = None
    kms_key: str | None = None

    @property
    def address(self) -> str:
        return self.resource.address


@dataclass(frozen=True)
class BackupConfig:
    """Backup / recovery configuration."""

    resource: Resource
    enabled: bool | None = None
    retention_days: int | None = None
    cross_region: bool | None = None

    @property
    def address(self) -> str:
        return self.resource.address


@dataclass(frozen=True)
class DetectiveControl:
    """A governing detective control (GuardDuty, Defender, SCC, Config rule)."""

    resource: Resource
    kind: str  # e.g. "guardduty", "config_rule", "security_center"
    enabled: bool | None = None
    parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return self.resource.address


@dataclass(frozen=True)
class OrgGuardrail:
    """An organization-level guardrail (SCP, Azure Policy, GCP Org Policy)."""

    resource: Resource
    kind: str  # "scp" | "azure_policy" | "org_policy"
    effect: str = ""  # Deny | Allow / enforcement mode
    targets: tuple[str, ...] = ()
    parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return self.resource.address
