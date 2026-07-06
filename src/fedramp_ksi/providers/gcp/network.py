"""GCP network adapters → normalized NetworkRule (SPEC §5).

Maps google_compute_firewall into NetworkRule. Each allow/deny block becomes an
entry; ports are parsed from the block's ``ports`` list; source/destination
ranges provide the CIDRs.
"""

from __future__ import annotations

from typing import Any

from ...model import NetworkRule, NetworkRuleEntry, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


def _parse_port(p: str) -> tuple[int | None, int | None]:
    if "-" in p:
        lo, hi = p.split("-", 1)
        return int(lo), int(hi)
    return int(p), int(p)


def _entries(
    blocks: Any, direction: str, action: str, cidrs: tuple[str, ...]
) -> list[NetworkRuleEntry]:
    out: list[NetworkRuleEntry] = []
    for b in blocks if isinstance(blocks, list) else [blocks]:
        if not isinstance(b, dict):
            continue
        protocol = str(b.get("protocol", "all")).lower()
        ports = b.get("ports") or []
        if not ports:
            out.append(NetworkRuleEntry(direction, protocol, None, None, cidrs, action))
        for p in ports:
            frm, to = _parse_port(str(p))
            out.append(NetworkRuleEntry(direction, protocol, frm, to, cidrs, action))
    return out


@adapter("google_compute_firewall")
def adapt_firewall(res: Resource, graph: ResourceGraph) -> None:
    direction = "egress" if str(res.get("direction", "INGRESS")).upper() == "EGRESS" else "ingress"
    if direction == "ingress":
        cidrs = tuple(str(c) for c in (res.get("source_ranges") or []))
    else:
        cidrs = tuple(str(c) for c in (res.get("destination_ranges") or []))
    entries = _entries(res.get("allow"), direction, "allow", cidrs)
    entries += _entries(res.get("deny"), direction, "deny", cidrs)
    graph.network_rules.append(
        NetworkRule(
            resource=res,
            ingress=tuple(e for e in entries if e.direction == "ingress"),
            egress=tuple(e for e in entries if e.direction == "egress"),
        )
    )
