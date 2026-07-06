"""AWS network adapters → normalized NetworkRule (SPEC §5).

Maps aws_security_group (inline ingress/egress), the standalone
aws_security_group_rule, and the newer aws_vpc_security_group_{ingress,egress}_rule
into normalized NetworkRule groups so KSI evaluators reason over one model.
"""

from __future__ import annotations

from typing import Any

from ...model import NetworkRule, NetworkRuleEntry, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _entry_from_block(direction: str, block: dict[str, Any]) -> NetworkRuleEntry:
    cidrs = tuple(_as_list(block.get("cidr_blocks")) + _as_list(block.get("ipv6_cidr_blocks")))
    protocol = str(block.get("protocol", "")).lower()
    from_port = block.get("from_port")
    to_port = block.get("to_port")
    # protocol "-1" (all) has no meaningful port range.
    if protocol in ("-1", "all"):
        from_port, to_port = None, None
    return NetworkRuleEntry(
        direction=direction,
        protocol=protocol or "-1",
        from_port=from_port if isinstance(from_port, int) else None,
        to_port=to_port if isinstance(to_port, int) else None,
        cidrs=tuple(str(c) for c in cidrs),
        action="allow",
    )


@adapter("aws_security_group")
def adapt_security_group(res: Resource, graph: ResourceGraph) -> None:
    ingress = tuple(_entry_from_block("ingress", b) for b in _as_list(res.get("ingress")))
    egress = tuple(_entry_from_block("egress", b) for b in _as_list(res.get("egress")))
    # aws_security_group with no egress block ⇒ Terraform manages egress and
    # leaves it empty (deny-all egress). We record whether egress was declared.
    graph.network_rules.append(
        NetworkRule(
            resource=res,
            ingress=ingress,
            egress=egress,
            default_deny_egress=(len(egress) == 0),
        )
    )


@adapter("aws_security_group_rule")
def adapt_security_group_rule(res: Resource, graph: ResourceGraph) -> None:
    direction = str(res.get("type", "ingress"))  # "ingress" | "egress"
    entry = _entry_from_block(direction, res.attributes)
    graph.network_rules.append(
        NetworkRule(
            resource=res,
            ingress=(entry,) if direction == "ingress" else (),
            egress=(entry,) if direction == "egress" else (),
        )
    )


@adapter("aws_vpc_security_group_ingress_rule")
def adapt_vpc_ingress_rule(res: Resource, graph: ResourceGraph) -> None:
    cidr = res.get("cidr_ipv4") or res.get("cidr_ipv6")
    entry = NetworkRuleEntry(
        direction="ingress",
        protocol=str(res.get("ip_protocol", "-1")).lower(),
        from_port=res.get("from_port") if isinstance(res.get("from_port"), int) else None,
        to_port=res.get("to_port") if isinstance(res.get("to_port"), int) else None,
        cidrs=(str(cidr),) if cidr else (),
    )
    graph.network_rules.append(NetworkRule(resource=res, ingress=(entry,)))


@adapter("aws_vpc_security_group_egress_rule")
def adapt_vpc_egress_rule(res: Resource, graph: ResourceGraph) -> None:
    cidr = res.get("cidr_ipv4") or res.get("cidr_ipv6")
    entry = NetworkRuleEntry(
        direction="egress",
        protocol=str(res.get("ip_protocol", "-1")).lower(),
        from_port=res.get("from_port") if isinstance(res.get("from_port"), int) else None,
        to_port=res.get("to_port") if isinstance(res.get("to_port"), int) else None,
        cidrs=(str(cidr),) if cidr else (),
    )
    graph.network_rules.append(NetworkRule(resource=res, egress=(entry,)))
