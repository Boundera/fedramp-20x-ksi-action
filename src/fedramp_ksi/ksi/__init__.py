"""KSI evaluator modules.

Each module registers its evaluator via ``@register_evaluator`` at import time.
``load_all`` auto-discovers and imports every evaluator module in this package,
so adding a KSI is a new module + fixtures — no edits here (SPEC §1.8).
"""

from __future__ import annotations

import importlib
import pkgutil

_loaded = False


def load_all() -> None:
    global _loaded
    if _loaded:
        return
    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")
    _loaded = True


__all__ = ["load_all"]
