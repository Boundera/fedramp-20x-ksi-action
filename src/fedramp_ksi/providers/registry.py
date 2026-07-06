"""Provider-adapter registry.

Adapters translate concrete Terraform resource types into normalized model
objects (SPEC §5). Each adapter registers against one or more resource types and
mutates the :class:`ResourceGraph` in place. ``build_graph`` walks the generic
resources produced by the loader and dispatches to the registered adapters, so
adding provider coverage is additive — no changes to the loader or engine.
"""

from __future__ import annotations

from collections.abc import Callable

from ..model import Provider, Resource
from ..model.graph import ResourceGraph

AdapterFn = Callable[[Resource, ResourceGraph], None]

_ADAPTERS: dict[str, list[AdapterFn]] = {}


def adapter(*resource_types: str) -> Callable[[AdapterFn], AdapterFn]:
    """Register ``fn`` as an adapter for each of ``resource_types``."""

    def deco(fn: AdapterFn) -> AdapterFn:
        for rt in resource_types:
            _ADAPTERS.setdefault(rt, []).append(fn)
        return fn

    return deco


def _ensure_adapters_loaded() -> None:
    # Importing the provider packages registers their adapters via @adapter.
    from . import aws, azure, gcp  # noqa: F401


def build_graph(
    resources: list[Resource],
    providers: tuple[Provider, ...] | None = None,
) -> ResourceGraph:
    """Build a normalized ResourceGraph from generic loader Resources."""
    _ensure_adapters_loaded()
    graph = ResourceGraph()
    for r in resources:
        if providers and r.provider not in providers:
            continue
        graph.resources.append(r)
        graph.providers_detected.add(r.provider.value)
        for fn in _ADAPTERS.get(r.type, []):
            fn(r, graph)
    return graph
