"""Tests for action.src.frmr_loader.

Verifies that the bundled FRMR JSON loads cleanly, indicator resolution works
for both canonical mnemonic IDs and legacy numeric IDs (via `fka`), and that
case-insensitive matching is honored.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from action.src.frmr_loader import (
    FRMRDocument,
    KSIIndicator,
    load_frmr,
    resolve_requested_ksi_ids,
)


@pytest.fixture(autouse=True)
def _set_frmr_dir() -> None:
    """Ensure FRMR_BUNDLE_DIR points at the repo's bundled FRMR data."""
    repo_root = Path(__file__).resolve().parents[1]
    os.environ["FRMR_BUNDLE_DIR"] = str(repo_root / "data" / "frmr")
    # Clear the lru_cache so each test gets a fresh load.
    load_frmr.cache_clear()


class TestLoadFRMR:
    def test_loads_v0_9_43_beta(self) -> None:
        frmr = load_frmr()
        assert isinstance(frmr, FRMRDocument)
        assert frmr.version == "0.9.43-beta"
        assert frmr.last_updated == "2026-04-08"

    def test_has_11_families(self) -> None:
        frmr = load_frmr()
        assert len(frmr.family_codes) == 11
        # The 11 expected families in v0.9.43-beta
        expected = {"AFR", "CMT", "CNA", "CED", "IAM", "INR", "MLA", "PIY", "RPL", "SVC", "SCR"}
        assert set(frmr.family_codes) == expected

    def test_has_60_indicators(self) -> None:
        frmr = load_frmr()
        assert len(frmr.indicators_by_id) == 60


class TestResolveByCanonicalID:
    def test_resolves_mla_evc(self) -> None:
        ind = load_frmr().resolve("KSI-MLA-EVC")
        assert isinstance(ind, KSIIndicator)
        assert ind.id == "KSI-MLA-EVC"
        assert ind.fka == "KSI-MLA-05"
        assert ind.name == "Evaluating Configurations"
        assert ind.family == "MLA"

    def test_resolves_cna_rnt(self) -> None:
        ind = load_frmr().resolve("KSI-CNA-RNT")
        assert ind.id == "KSI-CNA-RNT"
        assert ind.fka == "KSI-CNA-01"
        assert "Restricting Network Traffic" == ind.name

    def test_resolves_iam_mfa(self) -> None:
        ind = load_frmr().resolve("KSI-IAM-MFA")
        assert ind.id == "KSI-IAM-MFA"
        assert ind.fka == "KSI-IAM-01"


class TestResolveByLegacyFKA:
    def test_mla_05_maps_to_mla_evc(self) -> None:
        ind = load_frmr().resolve("KSI-MLA-EVC")
        assert ind.id == "KSI-MLA-EVC"

    def test_cna_01_maps_to_cna_rnt(self) -> None:
        ind = load_frmr().resolve("KSI-CNA-RNT")
        assert ind.id == "KSI-CNA-RNT"

    def test_iam_01_maps_to_iam_mfa(self) -> None:
        ind = load_frmr().resolve("KSI-IAM-01")
        assert ind.id == "KSI-IAM-MFA"


class TestCaseInsensitive:
    def test_lowercase_canonical(self) -> None:
        ind = load_frmr().resolve("ksi-mla-evc")
        assert ind.id == "KSI-MLA-EVC"

    def test_mixed_case_legacy(self) -> None:
        ind = load_frmr().resolve("Ksi-Mla-05")
        assert ind.id == "KSI-MLA-EVC"

    def test_whitespace_trimmed(self) -> None:
        ind = load_frmr().resolve("  KSI-MLA-EVC  ")
        assert ind.id == "KSI-MLA-EVC"


class TestUnresolvable:
    def test_raises_keyerror_for_unknown(self) -> None:
        with pytest.raises(KeyError):
            load_frmr().resolve("KSI-FAKE-XXX")

    def test_raises_keyerror_for_garbage(self) -> None:
        with pytest.raises(KeyError):
            load_frmr().resolve("not-a-ksi-id")


class TestIndicatorMetadata:
    def test_carries_nist_controls(self) -> None:
        ind = load_frmr().resolve("KSI-MLA-EVC")
        # KSI-MLA-EVC should have at least one 800-53 control mapping
        assert len(ind.nist_800_53_controls) > 0

    def test_statement_is_populated(self) -> None:
        ind = load_frmr().resolve("KSI-MLA-EVC")
        assert "evaluate" in ind.statement.lower()
        assert "configuration" in ind.statement.lower()


class TestResolveRequested:
    def test_resolves_mixed_canonical_and_fka(self) -> None:
        resolved = resolve_requested_ksi_ids(["KSI-MLA-EVC", "KSI-CNA-RNT"])
        ids = [ind.id for ind in resolved]
        assert ids == ["KSI-MLA-EVC", "KSI-CNA-RNT"]

    def test_dedupes(self) -> None:
        resolved = resolve_requested_ksi_ids(["KSI-MLA-EVC", "KSI-MLA-EVC", "KSI-MLA-EVC"])
        ids = [ind.id for ind in resolved]
        assert ids == ["KSI-MLA-EVC"]

    def test_preserves_order(self) -> None:
        resolved = resolve_requested_ksi_ids(["KSI-CNA-RNT", "KSI-MLA-EVC"])
        ids = [ind.id for ind in resolved]
        assert ids == ["KSI-CNA-RNT", "KSI-MLA-EVC"]
