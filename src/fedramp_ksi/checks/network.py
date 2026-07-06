"""Reusable network check primitives (SPEC §5).

Shared by the network-facing KSIs (CNA-RNT, CNA-MAT, ...). These operate on the
normalized :class:`NetworkRule` model, so they are provider-agnostic.
"""

from __future__ import annotations

from ..model import NetworkRule, NetworkRuleEntry

# CIDRs that mean "the entire internet".
WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# Administrative / sensitive service ports that must never be world-open.
# port -> human label
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker (plaintext)",
    2376: "Docker",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5984: "CouchDB",
    6379: "Redis",
    7001: "WebLogic",
    8020: "HDFS",
    9200: "Elasticsearch",
    9300: "Elasticsearch (transport)",
    11211: "Memcached",
    27017: "MongoDB",
}


def is_world_open(entry: NetworkRuleEntry) -> bool:
    """True if the rule entry allows any of the world CIDRs."""
    return any(c in WORLD_CIDRS for c in entry.cidrs)


def world_open_sensitive_ports(entry: NetworkRuleEntry) -> list[tuple[int, str]]:
    """Return (port, label) pairs for sensitive ports this entry opens to the world."""
    if entry.action != "allow" or entry.direction != "ingress" or not is_world_open(entry):
        return []
    hits: list[tuple[int, str]] = []
    for port, label in SENSITIVE_PORTS.items():
        if entry.covers_port(port):
            hits.append((port, label))
    return hits


def unrestricted_egress_entries(rule: NetworkRule) -> list[NetworkRuleEntry]:
    """Egress entries that allow all traffic to the world (0.0.0.0/0)."""
    return [e for e in rule.egress if e.action == "allow" and is_world_open(e)]


def has_explicit_ingress(rule: NetworkRule) -> bool:
    return len(rule.ingress) > 0
