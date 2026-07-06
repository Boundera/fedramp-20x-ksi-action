# Build Decisions

Ambiguities/corrections resolved during the build, per BUILD_PROMPT guidance
(state the issue, pick the most defensible option, record it, keep moving).

## D1 — Ruleset provenance: bundled beta ≠ pinned 2026.06.24.01

**Issue.** The repo shipped `data/frmr/FRMR.v0.9.43-beta.json` (60 indicators / 11
themes, including the `AFR` assurance theme and IDs like `KSI-SVC-SNT`,
`KSI-CED-DET…`, `KSI-IAM-MFA`). The SPEC (§0, §8) pins the finalized
**FedRAMP Consolidated Rules `2026.06.24.01`** — exactly **46 KSIs / 10 themes**.
The beta set does not match the SPEC's 46 (different mnemonics for CED, SVC-SIN;
extra IAM-MFA; extra AFR theme).

**Resolution.** Bundled the authoritative `2026.06.24.01` consolidated rules from
`FedRAMP/rules` at `data/ruleset/fedramp-consolidated-rules.2026.06.24.01.json`
(sha256 `49a612c8f72e499cfe6df7b27a60a8a360d58cab1fc64591258ec65183b9a1c2`,
recorded in `data/ruleset/MANIFEST.json`). Its KSI section contains exactly the
46 KSIs / 10 themes in SPEC §7, and `varies_by_class` confirms CNA-EIS, MLA-ALA,
SVC-VCM, SVC-PRR, SVC-RUD are optional@B / required@C — matching the SPEC.

The new engine (`src/fedramp_ksi/`) is driven by this pinned ruleset. The legacy
`data/frmr/` bundle and `action/src/frmr_loader.py` remain until the two existing
KSIs are migrated onto the new engine (SPEC §15.12), then are removed.

## D2 — Registry is the source of truth for dispositions

**Issue.** The ruleset JSON carries statements/controls/class-variation but not the
enforce/advisory/manual **disposition** — that is a build decision (SPEC §7).

**Resolution.** `src/fedramp_ksi/registry.py` holds the 46-KSI disposition table
transcribed from SPEC §7. A completeness test (`tests/unit/test_registry_completeness.py`)
asserts a bijection with the ruleset and the per-class totals
(22/12/12 base; 25/9/12 at Class C).

## D3 — Evidence output aligned to the FedRAMP SDR schema

**Issue.** SPEC calls for a signed evidence pack; the user asked to align output to the
FedRAMP Security Decision Record (SDR) schema's KSI section (informative, not required).

**Resolution.** Bundled the SDR schema at
`data/schemas/fedramp-security-decision-record-schema-2026-06-24.json`. The evidence
reporter emits a `keySecurityIndicators` array conforming to it: each item carries
`ksiId`, `ksiImplementation`, `ksiValidation`, `ksiAssesment` (sic), `ksiTests`,
`ksiEvidence[]`. This is emitted alongside (not instead of) the native manifest + SARIF.
