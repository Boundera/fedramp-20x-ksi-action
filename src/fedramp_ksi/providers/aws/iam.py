"""AWS IAM adapters → normalized IamPolicyStatement (SPEC §5).

Parses IAM policy documents (the resolved ``policy`` JSON in the plan) into
normalized statements so IAM KSIs reason over effect/actions/resources rather
than raw JSON. Static access keys are left as generic resources for the
anti-pattern check (IAM-SNU) to find by type.
"""

from __future__ import annotations

import json
from typing import Any

from ...model import IamPolicyStatement, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter

_POLICY_TYPES = (
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return (str(value),)


def _parse_policy_document(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            return []
    elif isinstance(raw, dict):
        doc = raw
    else:
        return []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict)]


@adapter(*_POLICY_TYPES)
def adapt_iam_policy(res: Resource, graph: ResourceGraph) -> None:
    for stmt in _parse_policy_document(res.get("policy")):
        principal = stmt.get("Principal", {})
        principals: tuple[str, ...] = ()
        if isinstance(principal, dict):
            vals: list[str] = []
            for v in principal.values():
                vals.extend(_as_tuple(v))
            principals = tuple(vals)
        elif isinstance(principal, str):
            principals = (principal,)
        graph.iam_statements.append(
            IamPolicyStatement(
                resource=res,
                effect=str(stmt.get("Effect", "Allow")),
                actions=_as_tuple(stmt.get("Action")),
                resources=_as_tuple(stmt.get("Resource")),
                principals=principals,
                conditions=stmt.get("Condition", {})
                if isinstance(stmt.get("Condition"), dict)
                else {},
            )
        )
