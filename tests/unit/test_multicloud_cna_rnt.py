"""CNA-RNT across all three clouds — proves the normalized model (SPEC §5)."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass, Provider, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture


def _status(provider_dir, name):
    resources = load_plan_file(fixture(provider_dir, "cna-rnt", name))
    er = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    return er.results[0].status


@pytest.mark.parametrize("cloud", ["azure", "gcp"])
def test_compliant_passes(cloud) -> None:
    assert _status(cloud, "compliant.json") == Status.PASS


@pytest.mark.parametrize("cloud", ["azure", "gcp"])
def test_violating_fails(cloud) -> None:
    assert _status(cloud, "violating.json") == Status.FAIL


def test_azure_internet_alias_treated_as_world() -> None:
    r = load_plan_file(fixture("azure", "cna-rnt", "violating.json"))
    g = build_graph(r)
    # "Internet" was normalized to 0.0.0.0/0 in the ingress entry.
    assert any("0.0.0.0/0" in e.cidrs for nr in g.network_rules for e in nr.ingress)
    assert g.providers_detected == {"azure"}


def test_provider_scope_excludes_other_clouds() -> None:
    resources = load_plan_file(fixture("gcp", "cna-rnt", "violating.json"))
    er = Engine().evaluate(
        build_graph(resources, providers=(Provider.AWS,)),
        ksi_ids=["KSI-CNA-RNT"],
        target_class=AuthClass.C,
    )
    # GCP resources filtered out ⇒ nothing in scope ⇒ N/A.
    assert er.results[0].status == Status.NA
