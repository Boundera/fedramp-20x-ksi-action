"""Terraform plan-JSON loader (SPEC §4, principle #2).

Parses ``terraform show -json`` output into normalized generic
:class:`~fedramp_ksi.model.resources.Resource` objects. Operating on the
resolved plan (not raw HCL) means modules, ``count``/``for_each``, variables,
and locals are already resolved by Terraform — a violation nested inside a
module is caught, not missed.

Handles both plan output (``planned_values``) and state output (``values``).
Resources being destroyed are excluded (they are not part of the post-apply
intended state). Unknown-after-apply attributes are recorded in
``Resource.unknown_keys`` so evaluators can emit PARTIAL/N/A rather than a
false PASS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..model import Provider, Resource, SourceRef


class PlanLoadError(ValueError):
    """Raised when the plan JSON is malformed or unreadable."""


_PROVIDER_PREFIX = {
    "aws": Provider.AWS,
    "azurerm": Provider.AZURE,
    "azuread": Provider.AZURE,
    "azapi": Provider.AZURE,
    "google": Provider.GCP,
    "google-beta": Provider.GCP,
}


def provider_for_type(resource_type: str, provider_name: str = "") -> Provider | None:
    """Infer the normalized provider from a resource type or provider name."""
    # provider_name looks like "registry.terraform.io/hashicorp/aws"
    if provider_name:
        short = provider_name.rstrip("/").split("/")[-1]
        if short in _PROVIDER_PREFIX:
            return _PROVIDER_PREFIX[short]
    prefix = resource_type.split("_", 1)[0]
    return _PROVIDER_PREFIX.get(prefix)


def load_plan_file(path: str | Path) -> list[Resource]:
    """Load and parse a ``terraform show -json`` file into Resources."""
    p = Path(path)
    if not p.is_file():
        raise PlanLoadError(f"Plan JSON not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PlanLoadError(f"Plan JSON is not valid JSON: {exc}") from exc
    return load_plan(raw)


def load_plan(plan: dict[str, Any]) -> list[Resource]:
    """Parse a parsed ``terraform show -json`` document into Resources."""
    if not isinstance(plan, dict):
        raise PlanLoadError("Plan JSON root must be an object")

    values = plan.get("planned_values") or plan.get("values")
    if not values:
        # An empty plan (no resources) is valid → no resources, not an error.
        if "format_version" in plan or "terraform_version" in plan:
            return []
        raise PlanLoadError("Plan JSON missing 'planned_values'/'values'")

    root = values.get("root_module", {})

    # Map of address → after_unknown dict, and set of destroy-only addresses.
    unknown_by_addr: dict[str, Any] = {}
    destroy_only: set[str] = set()
    for change in plan.get("resource_changes", []) or []:
        addr = change.get("address", "")
        actions = (change.get("change") or {}).get("actions", [])
        if actions == ["delete"]:
            destroy_only.add(addr)
        after_unknown = (change.get("change") or {}).get("after_unknown")
        if after_unknown:
            unknown_by_addr[addr] = after_unknown

    resources: list[Resource] = []
    _walk_module(root, resources, unknown_by_addr, destroy_only, module_path="")
    return resources


def _walk_module(
    module: dict[str, Any],
    out: list[Resource],
    unknown_by_addr: dict[str, Any],
    destroy_only: set[str],
    module_path: str,
) -> None:
    for res in module.get("resources", []) or []:
        address = res.get("address", "")
        if address in destroy_only:
            continue
        rtype = res.get("type", "")
        provider = provider_for_type(rtype, res.get("provider_name", ""))
        if provider is None:
            continue  # unsupported provider — skipped (not an error)
        values = res.get("values", {}) or {}
        unknown_keys = _unknown_keys(unknown_by_addr.get(address))
        out.append(
            Resource(
                address=address,
                type=rtype,
                provider=provider,
                name=res.get("name", ""),
                attributes=values,
                source=SourceRef(file=module_path or "root", line=None),
                unknown_keys=unknown_keys,
                mode=res.get("mode", "managed"),
            )
        )

    for child in module.get("child_modules", []) or []:
        child_path = child.get("address", module_path)
        _walk_module(child, out, unknown_by_addr, destroy_only, child_path)


def _unknown_keys(after_unknown: Any) -> tuple[str, ...]:
    """Extract top-level attribute names that are unknown-after-apply."""
    if not isinstance(after_unknown, dict):
        return ()
    keys: list[str] = []
    for key, val in after_unknown.items():
        # val is True (whole attr unknown) or a nested structure (partially).
        if val is True or (isinstance(val, (list, dict)) and val):
            keys.append(key)
    return tuple(keys)
