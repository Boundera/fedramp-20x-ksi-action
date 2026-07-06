"""KSI evaluator modules. Importing a module registers its evaluator."""

from __future__ import annotations


def load_all() -> None:
    """Import every KSI evaluator module so it registers with the registry."""
    from . import cna_rnt  # noqa: F401


__all__ = ["load_all"]
