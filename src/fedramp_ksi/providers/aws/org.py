"""AWS organization-guardrail adapters → normalized OrgGuardrail (SPEC §5)."""

from __future__ import annotations

from ...model import OrgGuardrail, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


@adapter("aws_organizations_policy")
def adapt_scp(res: Resource, graph: ResourceGraph) -> None:
    graph.org_guardrails.append(
        OrgGuardrail(
            resource=res,
            kind="scp",
            parameters={
                "type": res.get("type", "SERVICE_CONTROL_POLICY"),
                "content": res.get("content"),
            },
        )
    )
