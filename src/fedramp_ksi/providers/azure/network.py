"""Azure network adapters → normalized NetworkRule (SPEC §5).

Maps azurerm_network_security_rule (standalone) and azurerm_network_security_group
(inline security_rule) into NetworkRule. Azure source prefixes "Internet"/"*"
mean the whole internet and are normalized to 0.0.0.0/0 so the provider-agnostic
checks work unchanged.
"""

from __future__ import annotations

from typing import Any

from ...model import NetworkRule, NetworkRuleEntry, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter

_WORLD_ALIASES = {"internet", "*", "any"}


def _norm_cidrs(*values: Any) -> tuple[str, ...]:
    out: list[str] = []
    for v in values:
        if v is None:
            continue
        items = v if isinstance(v, list) else [v]
        for item in items:
            s = str(item)
            out.append("0.0.0.0/0" if s.lower() in _WORLD_ALIASES else s)
    return tuple(out)


def _ports(block: dict[str, Any]) -> tuple[int | None, int | None]:
    rng = block.get("destination_port_range")
    ranges = block.get("destination_port_ranges")
    candidate = rng if rng not in (None, "") else (ranges[0] if ranges else None)
    if candidate in (None, "*", ""):
        return None, None
    s = str(candidate)
    if "-" in s:
        lo, hi = s.split("-", 1)
        return int(lo), int(hi)
    return int(s), int(s)


def _entry(block: dict[str, Any]) -> NetworkRuleEntry:
    direction = (
        "ingress" if str(block.get("direction", "Inbound")).lower() == "inbound" else "egress"
    )
    frm, to = _ports(block)
    src = _norm_cidrs(block.get("source_address_prefix"), block.get("source_address_prefixes"))
    return NetworkRuleEntry(
        direction=direction,
        protocol=str(block.get("protocol", "*")).lower(),
        from_port=frm,
        to_port=to,
        cidrs=src
        if direction == "ingress"
        else _norm_cidrs(
            block.get("destination_address_prefix"), block.get("destination_address_prefixes")
        ),
        action="allow" if str(block.get("access", "Allow")).lower() == "allow" else "deny",
    )


@adapter("azurerm_network_security_rule")
def adapt_nsg_rule(res: Resource, graph: ResourceGraph) -> None:
    entry = _entry(res.attributes)
    graph.network_rules.append(
        NetworkRule(
            resource=res,
            ingress=(entry,) if entry.direction == "ingress" else (),
            egress=(entry,) if entry.direction == "egress" else (),
        )
    )


@adapter("azurerm_network_security_group")
def adapt_nsg(res: Resource, graph: ResourceGraph) -> None:
    rules = res.get("security_rule") or []
    entries = [_entry(b) for b in (rules if isinstance(rules, list) else [rules])]
    graph.network_rules.append(
        NetworkRule(
            resource=res,
            ingress=tuple(e for e in entries if e.direction == "ingress"),
            egress=tuple(e for e in entries if e.direction == "egress"),
        )
    )
