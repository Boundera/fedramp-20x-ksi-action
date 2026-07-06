"""SPEC §15.1 — registry contains exactly the 46 KSIs with justified
dispositions, and the per-class totals hold.

These are *hard* acceptance gates: the disposition totals must match SPEC §7.
"""

from __future__ import annotations

from fedramp_ksi.model import AuthClass, Disposition
from fedramp_ksi.registry import all_entries, disposition_counts, get_entry
from fedramp_ksi.ruleset import load_ruleset


def test_registry_has_exactly_46_ksis() -> None:
    assert len(all_entries()) == 46
    ids = [e.ksi_id for e in all_entries()]
    assert len(set(ids)) == 46, "duplicate KSI ids in registry"


def test_registry_matches_ruleset_bijectively() -> None:
    rs = load_ruleset()
    registry_ids = {e.ksi_id for e in all_entries()}
    ruleset_ids = set(rs.ksis.keys())
    assert registry_ids == ruleset_ids, (
        f"registry vs ruleset mismatch: "
        f"only-in-registry={registry_ids - ruleset_ids} "
        f"only-in-ruleset={ruleset_ids - registry_ids}"
    )


def test_ruleset_is_pinned_2026_06_24_01() -> None:
    rs = load_ruleset()
    assert rs.version == "2026.06.24.01"
    assert len(rs.sha256) == 64


def test_base_disposition_totals() -> None:
    # Class A/B view: 22 enforce + 12 advisory + 12 manual (SPEC §7)
    counts = disposition_counts(AuthClass.A)
    assert counts[Disposition.ENFORCE] == 22
    assert counts[Disposition.ADVISORY] == 12
    assert counts[Disposition.MANUAL] == 12


def test_class_b_matches_base() -> None:
    counts = disposition_counts(AuthClass.B)
    assert counts[Disposition.ENFORCE] == 22
    assert counts[Disposition.ADVISORY] == 12
    assert counts[Disposition.MANUAL] == 12


def test_class_c_disposition_totals() -> None:
    # Class C: 3 advisory KSIs shift to enforce → 25 enforce + 9 advisory + 12 manual
    counts = disposition_counts(AuthClass.C)
    assert counts[Disposition.ENFORCE] == 25
    assert counts[Disposition.ADVISORY] == 9
    assert counts[Disposition.MANUAL] == 12


def test_class_c_shifters_are_the_expected_three() -> None:
    shifters = {
        e.ksi_id
        for e in all_entries()
        if e.disposition is Disposition.ADVISORY
        and e.disposition_for(AuthClass.C) is Disposition.ENFORCE
    }
    assert shifters == {"KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-VCM"}


def test_manual_ksis_have_no_providers() -> None:
    for e in all_entries():
        if e.disposition is Disposition.MANUAL:
            assert e.providers == (), f"{e.ksi_id} is MANUAL but declares providers"


def test_every_entry_resolves_in_ruleset_with_statement() -> None:
    rs = load_ruleset()
    for e in all_entries():
        ksi = rs.get(e.ksi_id)
        assert ksi.statement, f"{e.ksi_id} has empty statement"
        assert ksi.theme, f"{e.ksi_id} has empty theme"


def test_get_entry_is_case_insensitive() -> None:
    assert get_entry("ksi-cna-rnt").ksi_id == "KSI-CNA-RNT"
