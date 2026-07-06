"""Pinned FedRAMP ruleset loader (SPEC §8).

Loads the bundled consolidated rules (``2026.06.24.01`` by default), exposing
per-KSI metadata: id, theme, statement, related 800-53 controls, per-class
statement variation (optional/required), and the ruleset version + SHA-256 so
they can be recorded in every artifact.

The active ruleset file is named by ``data/ruleset/CURRENT.txt``; previous
files are retained for reproducibility. The version + hash come from the
sibling ``MANIFEST.json`` (verified against the file contents at load time).
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import AuthClass, ClassRequirement


@dataclass(frozen=True)
class KSIDefinition:
    """One Key Security Indicator as defined by the pinned ruleset."""

    id: str
    theme: str  # short_name, e.g. "CNA"
    theme_name: str  # e.g. "Cloud Native Architecture"
    name: str
    statement: str  # canonical statement (class C / base)
    controls: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    statements_by_class: dict[str, str] = field(default_factory=dict)
    requirement_by_class: dict[str, ClassRequirement] = field(default_factory=dict)

    def statement_for(self, cls: AuthClass) -> str:
        return self.statements_by_class.get(cls.value.lower(), self.statement)

    def requirement_for(self, cls: AuthClass) -> ClassRequirement:
        return self.requirement_by_class.get(cls.value.lower(), ClassRequirement.REQUIRED)


@dataclass(frozen=True)
class Ruleset:
    """Parsed, indexed ruleset with provenance."""

    version: str
    last_updated: str
    sha256: str
    source_file: str
    ksis: dict[str, KSIDefinition]

    def get(self, ksi_id: str) -> KSIDefinition:
        return self.ksis[ksi_id.strip().upper()]

    def __contains__(self, ksi_id: str) -> bool:
        return ksi_id.strip().upper() in self.ksis

    @property
    def provenance(self) -> dict[str, str]:
        return {
            "ruleset_version": self.version,
            "ruleset_last_updated": self.last_updated,
            "ruleset_sha256": self.sha256,
            "ruleset_source_file": self.source_file,
        }


def _bundle_dir() -> Path:
    env = os.environ.get("KSI_RULESET_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data" / "ruleset"


def _read_current(bundle_dir: Path) -> str:
    pointer = bundle_dir / "CURRENT.txt"
    if not pointer.is_file():
        raise FileNotFoundError(f"Ruleset pointer not found: {pointer}")
    name = pointer.read_text(encoding="utf-8").strip()
    if not name:
        raise ValueError(f"Ruleset pointer {pointer} is empty")
    return name


@functools.lru_cache(maxsize=4)
def load_ruleset(bundle_dir: str | None = None) -> Ruleset:
    """Load and parse the pinned ruleset, verifying its SHA-256."""
    directory = _bundle_dir() if bundle_dir is None else Path(bundle_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Ruleset directory does not exist: {directory}")

    filename = _read_current(directory)
    json_path = directory / filename
    raw_bytes = json_path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()

    manifest_path = directory / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    expected = manifest.get("sha256")
    if expected and expected != digest:
        raise ValueError(
            f"Ruleset hash mismatch for {json_path}: manifest={expected} actual={digest}"
        )

    raw = json.loads(raw_bytes)
    return _parse(raw, digest, filename)


def _parse(raw: dict[str, Any], digest: str, source_file: str) -> Ruleset:
    info = raw.get("info", {})
    version = info.get("version", "unknown")
    last_updated = info.get("last_updated", "unknown")

    ksi_section = raw.get("KSI", {})
    if not isinstance(ksi_section, dict):
        raise ValueError("Ruleset has no top-level 'KSI' dict")

    ksis: dict[str, KSIDefinition] = {}
    for _theme_key, theme in ksi_section.items():
        if not isinstance(theme, dict):
            continue
        theme_short = theme.get("short_name", _theme_key)
        theme_name = theme.get("name", theme_short)
        indicators = theme.get("indicators", {})
        items = (
            indicators.items()
            if isinstance(indicators, dict)
            else [(i.get("id", "?"), i) for i in indicators]
        )
        for ind_id, ind in items:
            if not isinstance(ind, dict):
                continue
            canonical = ind.get("id", ind_id)
            base_statement = ind.get("statement", "") or ""

            statements_by_class: dict[str, str] = {}
            requirement_by_class: dict[str, ClassRequirement] = {}
            vbc = ind.get("varies_by_class")
            if isinstance(vbc, dict):
                for cls, block in vbc.items():
                    if not isinstance(block, dict):
                        continue
                    stmt = block.get("statement", "")
                    statements_by_class[cls.lower()] = stmt
                    requirement_by_class[cls.lower()] = (
                        ClassRequirement.OPTIONAL
                        if "**optional:**" in stmt.lower() or "optional:" in stmt.lower()
                        else ClassRequirement.REQUIRED
                    )
                # canonical statement = strictest (class c) if present
                base_statement = statements_by_class.get("c") or base_statement

            controls = tuple(
                c if isinstance(c, str) else (c.get("control_id") or c.get("id") or "")
                for c in ind.get("controls", [])
            )
            ksis[canonical.upper()] = KSIDefinition(
                id=canonical,
                theme=theme_short,
                theme_name=theme_name,
                name=ind.get("name", canonical),
                statement=base_statement,
                controls=tuple(c for c in controls if c),
                terms=tuple(ind.get("terms", [])),
                statements_by_class=statements_by_class,
                requirement_by_class=requirement_by_class,
            )

    return Ruleset(
        version=version,
        last_updated=last_updated,
        sha256=digest,
        source_file=source_file,
        ksis=ksis,
    )
