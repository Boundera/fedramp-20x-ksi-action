"""SPEC §11/§15.6/§15.8 — reporters: SARIF, SDR conformance, determinism."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass
from fedramp_ksi.providers import build_graph
from fedramp_ksi.reporters import (
    RunMeta,
    build_manifest,
    build_report,
    build_sarif,
    build_sdr,
    build_summary,
    write_evidence_pack,
)

from .conftest import fixture

SDR_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "schemas"
    / "fedramp-security-decision-record-schema-2026-06-24.json"
)


def _report(fixture_path, meta=None):
    resources = load_plan_file(fixture_path)
    engine_result = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    return build_report(engine_result, meta=meta or RunMeta(generated_at="2026-01-01T00:00:00Z"))


# --- SARIF ------------------------------------------------------------------


def test_sarif_basic_shape() -> None:
    sarif = build_sarif(_report(fixture("aws", "cna-rnt", "violating.json")))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "fedramp-20x-ksi-action"
    assert run["properties"]["ruleset_version"] == "2026.06.24.01"
    assert run["results"], "violating plan should produce SARIF results"
    for res in run["results"]:
        assert res["ruleId"]
        assert res["level"] in ("error", "warning", "note", "none")
        assert res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_compliant_has_no_error_results() -> None:
    sarif = build_sarif(_report(fixture("aws", "cna-rnt", "compliant.json")))
    errors = [r for r in sarif["runs"][0]["results"] if r["level"] == "error"]
    assert errors == []


def test_sarif_rules_declared_for_each_result() -> None:
    sarif = build_sarif(_report(fixture("aws", "cna-rnt", "violating.json")))
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids


# --- SDR conformance --------------------------------------------------------


def _sdr_item_schema() -> dict:
    full = json.loads(SDR_SCHEMA.read_text())
    item = full["properties"]["keySecurityIndicators"]["items"]["keySecurityIndicator"]
    return {**item, "$defs": full["$defs"]}


def test_sdr_items_conform_to_sdr_schema() -> None:
    sdr = build_sdr(_report(fixture("aws", "cna-rnt", "violating.json")))
    schema = _sdr_item_schema()
    assert sdr["keySecurityIndicators"]
    for item in sdr["keySecurityIndicators"]:
        jsonschema.validate(item, schema)


def test_sdr_item_has_required_fields() -> None:
    sdr = build_sdr(_report(fixture("aws", "cna-rnt", "compliant.json")))
    item = sdr["keySecurityIndicators"][0]
    for key in (
        "ksiId",
        "ksiImplementation",
        "ksiValidation",
        "ksiAssesment",
        "ksiTests",
        "ksiEvidence",
    ):
        assert key in item
    assert item["ksiId"] == "KSI-CNA-RNT"


# --- Determinism (SPEC §15.8) ----------------------------------------------


def test_manifest_deterministic_ignoring_timestamps() -> None:
    r1 = _report(fixture("aws", "cna-rnt", "violating.json"))
    r2 = _report(fixture("aws", "cna-rnt", "violating.json"))
    m1 = build_manifest(r1)
    m2 = build_manifest(r2)
    assert m1 == m2
    # And byte-identical when serialized.
    assert json.dumps(m1, sort_keys=True) == json.dumps(m2, sort_keys=True)


def test_manifest_records_ruleset_hash() -> None:
    m = build_manifest(_report(fixture("aws", "cna-rnt", "violating.json")))
    assert m["ruleset"]["version"] == "2026.06.24.01"
    assert len(m["ruleset"]["sha256"]) == 64


def test_evidence_pack_written_with_checksums(tmp_path) -> None:
    report = _report(fixture("aws", "cna-rnt", "violating.json"))
    paths = write_evidence_pack(report, tmp_path)
    for key in ("manifest", "sarif", "sdr", "checksums"):
        assert paths[key].exists()
    checks = paths["checksums"].read_text().splitlines()
    assert any("manifest.json" in line for line in checks)
    # Checksums match the written files.
    import hashlib

    for line in checks:
        digest, name = line.split("  ")
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest


def test_summary_renders_gate_and_failures() -> None:
    summary = build_summary(_report(fixture("aws", "cna-rnt", "violating.json")))
    assert "FedRAMP 20x KSI Gate" in summary
    assert "FAIL" in summary
    assert "KSI-CNA-RNT" in summary


def test_findings_by_severity_only_counts_failures() -> None:
    report = _report(fixture("aws", "cna-rnt", "violating.json"))
    counts = report.findings_by_severity()
    assert counts["high"] >= 1  # SSH-to-world is high
