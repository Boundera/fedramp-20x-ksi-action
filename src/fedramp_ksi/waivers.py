"""Waivers & baseline suppression (SPEC §9).

A matching, unexpired waiver downgrades a FAIL to a recorded, suppressed finding
(still in the manifest with reason + approver + expiry). Expired or unmatched
waivers leave the finding live and gate-blocking. A baseline suppresses a
snapshot of pre-existing findings; findings not in the baseline stay live
(drift). Both are implemented as finding transforms consumed by the engine.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .model import Finding, Status


@dataclass(frozen=True)
class Waiver:
    ksi: str
    resource: str
    reason: str
    approved_by: str
    expires: date

    def matches(self, finding: Finding) -> bool:
        if finding.ksi_id.upper() != self.ksi.upper():
            return False
        # Resource may be an exact address or a glob (e.g. module.*.aws_s3_bucket.*).
        return fnmatch.fnmatch(finding.resource_address, self.resource)

    def is_active(self, today: date) -> bool:
        return today <= self.expires

    @property
    def ref(self) -> str:
        return (
            f"{self.ksi}:{self.resource} (approved_by={self.approved_by}, expires={self.expires})"
        )


def _parse_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def load_waivers(path: str | Path) -> list[Waiver]:
    p = Path(path)
    if not p.is_file():
        return []
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    waivers: list[Waiver] = []
    for entry in doc.get("waivers", []) or []:
        if "expires" not in entry:
            raise ValueError(f"Waiver for {entry.get('ksi')} is missing required 'expires' date.")
        waivers.append(
            Waiver(
                ksi=str(entry["ksi"]).strip(),
                resource=str(entry.get("resource", "*")).strip(),
                reason=str(entry.get("reason", "")),
                approved_by=str(entry.get("approved_by", "")),
                expires=_parse_date(entry["expires"]),
            )
        )
    return waivers


def waiver_transform(waivers: list[Waiver], today: date):
    """Return a finding transform that suppresses waived, unexpired FAILs."""

    def transform(findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            if f.status == Status.FAIL and not f.suppressed:
                match = next((w for w in waivers if w.matches(f) and w.is_active(today)), None)
                if match is not None:
                    out.append(f.with_waiver(match.ref))
                    continue
            out.append(f)
        return out

    return transform


# --- Baseline ---------------------------------------------------------------


def _fingerprint(f: Finding) -> str:
    return f"{f.ksi_id}|{f.check_id}|{f.resource_address}"


def load_baseline(path: str | Path) -> set[str]:
    p = Path(path)
    if not p.is_file():
        return set()
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return set(doc.get("baseline", []) or [])


def build_baseline(findings: list[Finding]) -> list[str]:
    """Fingerprints of current FAIL findings — snapshot for a baseline file."""
    return sorted({_fingerprint(f) for f in findings if f.status == Status.FAIL})


def baseline_transform(fingerprints: set[str]):
    """Return a transform that suppresses FAILs present in the baseline snapshot."""

    def transform(findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            if f.status == Status.FAIL and not f.suppressed and _fingerprint(f) in fingerprints:
                out.append(f.with_baseline())
            else:
                out.append(f)
        return out

    return transform
