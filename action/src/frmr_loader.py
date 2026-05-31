"""FRMR documentation loader.

Loads the FedRAMP Machine-Readable (FRMR) documentation bundled in this
repository under data/frmr/, resolves indicator metadata (id, name, statement,
fka, controls), and supports auto-mapping of legacy numeric IDs to current
mnemonic IDs via each indicator's `fka` field.

The bundled FRMR file is selected by reading data/frmr/CURRENT.txt, which
contains a single line naming the active JSON file. To upgrade the FRMR
version this action evaluates against:

  1. Drop the new FRMR JSON into data/frmr/.
  2. Update data/frmr/CURRENT.txt to name the new file.
  3. Bump this action's minor version.

The previous JSON files are preserved so that older versions of the action
can be re-run reproducibly.

FRMR documents are US Government works in the public domain (17 USC §105).
See data/frmr/README.md for full provenance.
"""

from __future__ import annotations

import functools
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class KSIIndicator:
    """One Key Security Indicator from FRMR.

    Carries both the current (mnemonic) ID and the legacy (numeric) ID,
    along with all metadata an evaluator needs.
    """

    id: str                              # canonical mnemonic e.g. "KSI-MLA-EVC"
    fka: str | None                      # formerly known as e.g. "KSI-MLA-05"
    family: str                          # family short_name e.g. "MLA"
    family_name: str                     # e.g. "Monitoring, Logging, and Auditing"
    name: str                            # e.g. "Evaluating Configurations"
    statement: str                       # verbatim FRMR requirement text
    nist_800_53_controls: tuple[str, ...] = field(default_factory=tuple)
    impact_levels: tuple[str, ...] = field(default_factory=tuple)
    retired: bool = False
    retired_note: str | None = None
    statement_varies_by_level: bool = False
    statements_by_level: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FRMRDocument:
    """Parsed FRMR documentation, indexed for fast lookup."""

    version: str
    last_updated: str
    indicators_by_id: dict[str, KSIIndicator]
    indicators_by_fka: dict[str, KSIIndicator]
    family_codes: tuple[str, ...]

    def resolve(self, id_or_fka: str) -> KSIIndicator:
        """Look up an indicator by current ID or legacy (fka) ID.

        Args:
            id_or_fka: An indicator ID. Either current mnemonic (e.g.,
                'KSI-MLA-EVC') or legacy numeric (e.g., 'KSI-MLA-05').

        Returns:
            The KSIIndicator.

        Raises:
            KeyError: If neither the current ID nor the fka matches.
        """
        normalized = id_or_fka.strip().upper()
        if normalized in self.indicators_by_id:
            return self.indicators_by_id[normalized]
        if normalized in self.indicators_by_fka:
            ind = self.indicators_by_fka[normalized]
            logger.info(
                "Auto-mapped legacy ID %s to current canonical ID %s via 'fka' field.",
                normalized,
                ind.id,
            )
            return ind
        raise KeyError(
            f"Indicator '{id_or_fka}' not found in FRMR {self.version}. "
            f"Available IDs include {sorted(self.indicators_by_id.keys())[:5]}..."
        )


def _bundle_dir() -> Path:
    """Resolve the directory holding bundled FRMR JSON files.

    Priority:
      1. FRMR_BUNDLE_DIR environment variable (set by action.yml).
      2. Repository-relative path: <repo_root>/data/frmr/.
    """
    env_dir = os.environ.get("FRMR_BUNDLE_DIR")
    if env_dir:
        return Path(env_dir)
    # frmr_loader.py lives at action/src/frmr_loader.py.
    # data/frmr/ lives at <repo_root>/data/frmr/.
    return Path(__file__).resolve().parents[2] / "data" / "frmr"


def _read_current_filename(bundle_dir: Path) -> str:
    """Read the CURRENT.txt pointer to the active FRMR JSON filename."""
    pointer = bundle_dir / "CURRENT.txt"
    if not pointer.is_file():
        raise FileNotFoundError(
            f"FRMR pointer file not found: {pointer}. "
            f"Expected a single-line file naming the active FRMR JSON."
        )
    name = pointer.read_text(encoding="utf-8").strip()
    if not name:
        raise ValueError(f"FRMR pointer file {pointer} is empty.")
    return name


@functools.lru_cache(maxsize=4)
def load_frmr(bundle_dir: str | None = None) -> FRMRDocument:
    """Load and parse the bundled FRMR document.

    Args:
        bundle_dir: Optional override for the bundle directory. If omitted,
            falls back to FRMR_BUNDLE_DIR env var, then <repo_root>/data/frmr.

    Returns:
        Parsed FRMRDocument with indicators indexed by id and fka.
    """
    if bundle_dir is None:
        directory = _bundle_dir()
    else:
        directory = Path(bundle_dir)

    if not directory.is_dir():
        raise FileNotFoundError(
            f"FRMR bundle directory does not exist: {directory}"
        )

    filename = _read_current_filename(directory)
    json_path = directory / filename
    if not json_path.is_file():
        raise FileNotFoundError(
            f"FRMR JSON file referenced by CURRENT.txt not found: {json_path}"
        )

    logger.info("Loading FRMR document from %s", json_path)
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    return _parse_frmr(raw)


def _parse_frmr(raw: dict[str, Any]) -> FRMRDocument:
    """Convert the raw JSON into an indexed FRMRDocument."""
    info = raw.get("info", {})
    version = info.get("version", "unknown")
    last_updated = info.get("last_updated", "unknown")

    ksi_section = raw.get("KSI", {})
    if not isinstance(ksi_section, dict):
        raise ValueError("FRMR document has no top-level 'KSI' dict.")

    indicators_by_id: dict[str, KSIIndicator] = {}
    indicators_by_fka: dict[str, KSIIndicator] = {}
    family_codes: list[str] = []

    for family_code, family in ksi_section.items():
        if not isinstance(family, dict):
            continue
        family_codes.append(family_code)
        family_name = family.get("name", family_code)
        indicators_raw = family.get("indicators", {})

        # Two shapes observed across FRMR releases:
        #   v0.9.43-beta: indicators is a dict keyed by ID (current).
        #   Earlier 25.x: indicators is a list of dicts each carrying its 'id'.
        items: list[tuple[str, dict[str, Any]]]
        if isinstance(indicators_raw, dict):
            items = list(indicators_raw.items())
        elif isinstance(indicators_raw, list):
            items = [(ind.get("id", "?"), ind) for ind in indicators_raw]
        else:
            continue

        for ind_id, ind in items:
            if not isinstance(ind, dict):
                continue
            canonical_id = ind.get("id", ind_id)
            statement = ind.get("statement", "") or ""
            varies = "varies_by_level" in ind
            statements_by_level: dict[str, str] = {}
            if varies:
                vbl = ind["varies_by_level"]
                if isinstance(vbl, dict):
                    for level, level_block in vbl.items():
                        if isinstance(level_block, dict):
                            statements_by_level[level] = level_block.get("statement", "")
                # Pick moderate (or first) as the canonical single statement
                statement = (
                    statements_by_level.get("moderate")
                    or next(iter(statements_by_level.values()), "")
                )

            controls_raw = ind.get("controls", [])
            controls: list[str] = []
            for c in controls_raw:
                if isinstance(c, dict):
                    cid = c.get("control_id") or c.get("id")
                    if cid:
                        controls.append(cid)
                elif isinstance(c, str):
                    controls.append(c)

            impact = ind.get("impact", {})
            levels = tuple(k for k, v in impact.items() if v) if isinstance(impact, dict) else ()

            indicator = KSIIndicator(
                id=canonical_id,
                fka=ind.get("fka") or None,
                family=family.get("short_name", family_code),
                family_name=family_name,
                name=ind.get("name", canonical_id),
                statement=statement,
                nist_800_53_controls=tuple(controls),
                impact_levels=levels,
                retired=bool(ind.get("retired", False)),
                retired_note=ind.get("note") if ind.get("retired") else None,
                statement_varies_by_level=varies,
                statements_by_level=statements_by_level,
            )

            indicators_by_id[indicator.id.upper()] = indicator
            if indicator.fka:
                indicators_by_fka[indicator.fka.upper()] = indicator

    return FRMRDocument(
        version=version,
        last_updated=last_updated,
        indicators_by_id=indicators_by_id,
        indicators_by_fka=indicators_by_fka,
        family_codes=tuple(family_codes),
    )


def resolve_requested_ksi_ids(requested: list[str]) -> list[KSIIndicator]:
    """Resolve a user-supplied list of KSI IDs into KSIIndicator objects.

    Accepts both current mnemonics and legacy numeric IDs. Emits a warning
    for each legacy ID that was auto-mapped.

    Args:
        requested: List of strings from the `ksi_ids` input.

    Returns:
        List of resolved KSIIndicator objects, in the requested order,
        deduplicated.

    Raises:
        KeyError: If any requested ID cannot be resolved.
    """
    frmr = load_frmr()
    resolved: list[KSIIndicator] = []
    seen: set[str] = set()
    for req in requested:
        ind = frmr.resolve(req)
        if ind.id not in seen:
            resolved.append(ind)
            seen.add(ind.id)
    return resolved
