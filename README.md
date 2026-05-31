# fedramp-20x-ksi-action

> A GitHub Action that evaluates Terraform IaC against FedRAMP 20x Key Security Indicators, generates a signed evidence pack, and posts results as a GitHub Check Run — without a vendor-operated server.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FedRAMP 20x](https://img.shields.io/badge/FedRAMP-20x-0B2545.svg)](https://www.fedramp.gov/)
[![FRMR](https://img.shields.io/badge/FRMR-v0.9.43--beta-1F6FEB.svg)](https://www.fedramp.gov/)
[![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF.svg?logo=github-actions)](https://github.com/marketplace?type=actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

For Cloud Service Providers preparing FedRAMP 20x submissions. Run this action in your CI to continuously verify your Terraform IaC against `KSI-MLA-EVC` (Evaluating Configurations) and `KSI-CNA-RNT` (Restricting Network Traffic). The action runs entirely inside your GitHub Actions runner, produces evidence artifacts you can hand to a 3PAO, and posts Check Runs on your commits — with no Boundera-operated backend in the loop. Customer evidence never leaves GitHub-managed infrastructure.

Maintained by [Boundera](https://boundera.io). Released under the MIT license.

---

## Why this exists

The original [`chukyjack/fedrampgpt-ksi-checker`](https://github.com/chukyjack/fedrampgpt-ksi-checker) had the same goal but used a GitHub App backed by a vendor-hosted webhook receiver to post Check Runs. That backend transited customer evidence through non-FedRAMP-authorized infrastructure — a real boundary problem for any CSP whose runtime is in scope for FedRAMP.

This action takes a different path:

- **No GitHub App.** No webhook receiver. No vendor-operated server.
- **The action itself posts Check Runs**, using the workflow's built-in `GITHUB_TOKEN`.
- **Evidence stays in GitHub Actions storage.** Nothing transits a Boundera server.
- **Bundled FRMR document.** The FedRAMP machine-readable spec is committed to this repo, so evaluations are hermetic and reproducible against a pinned version.

The trade-off: Check Runs appear under the "GitHub Actions" identity rather than a branded "FedRAMP KSI Checker" app icon. For most federal procurement teams, that's a fair price for eliminating the boundary problem. See [`docs/architecture-no-server.md`](docs/architecture-no-server.md) for the full reasoning.

## Quick start

Create `.github/workflows/fedramp-ksi.yml` in any repo that contains Terraform:

```yaml
name: FedRAMP KSI

on:
  schedule:
    - cron: '0 0 * * *'   # daily — required for KSI-MLA-EVC "persistent cycle"
  workflow_dispatch:       # manual triggers will FAIL the persistent-cycle check by design

permissions:
  contents: read
  actions: read
  checks: write            # required — the action fails fast if this is missing

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Boundera/fedramp-20x-ksi-action@v1
```

That's the entire integration. No app to install, no webhook to configure, no secret to set.

## What you get

After the first scheduled run:

- A **Check Run on every commit** showing PASS / FAIL / ERROR per indicator, the evaluation reasoning, and links to evidence.
- An **evidence artifact zip** uploaded to the workflow run, retained 90 days by default. Contains:
  - `evaluation_manifest.json` — the canonical machine-readable result
  - Terraform inventory and network inventory snapshots
  - `hashes.sha256` — SHA-256 over every evidence file for integrity
  - The full FRMR version your evaluation was scored against, for reproducibility

3PAOs review the artifact directly. No vendor portal involved.

## Inputs

| Name | Required | Default | Description |
|---|:---:|---|---|
| `root_paths` | no | `.` | Comma-separated paths to scan for Terraform. |
| `ksi_ids` | no | `KSI-MLA-EVC,KSI-CNA-RNT` | Indicators to evaluate. Legacy IDs (`KSI-MLA-05`, `KSI-CNA-01`) accepted and auto-mapped. |
| `terraform_version` | no | `""` | Pin a specific Terraform version. Default uses the pre-installed one. |
| `python_version` | no | `3.11` | Python version for the action's runtime. |
| `post_check_run` | no | `true` | Set `false` to skip the Check Run API call. Useful for local testing. |
| `artifact_prefix` | no | `evidence` | Prefix for the uploaded evidence artifact names. |
| `evidence_retention_days` | no | `90` | GitHub Actions artifact retention period. |

## Outputs

| Name | Description |
|---|---|
| `status` | Worst status across all evaluated KSIs: `PASS` / `FAIL` / `ERROR`. |
| `mla_evc_status` | `KSI-MLA-EVC` result. |
| `cna_rnt_status` | `KSI-CNA-RNT` result. |
| `cna_01_status` | Alias for `cna_rnt_status` — preserved for compatibility with the original action. Removed in v1.0. |
| `evidence_dir` | Absolute path to the evidence directory inside the workspace. |
| `artifact_names` | JSON array of uploaded artifact names. |
| `check_run_ids` | JSON array of created Check Run IDs (empty if `post_check_run=false`). |
| `summary` | Markdown summary of the run. |

## Coverage in v0.1.0

| Indicator | FKA | Family | Theme |
|---|---|---|---|
| **`KSI-MLA-EVC`** Evaluating Configurations | `KSI-MLA-05` | MLA | Persistently evaluate and test the configuration of machine-based information resources, especially IaC. |
| **`KSI-CNA-RNT`** Restricting Network Traffic | `KSI-CNA-01` | CNA | Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic. |

The remaining 58 indicators across 9 KSI families are out of scope for this action. They're covered in [`Boundera/fedramp-20x-toolkit`](https://github.com/Boundera/fedramp-20x-toolkit) (KSI evidence mappings) and in Boundera's commercial product (automated evidence collection across the full FedRAMP 20x scope).

## How evidence is generated

```
┌──────────────────────────────────────────────────────────────────┐
│   Customer GitHub Actions runner (ubuntu-latest)                 │
│                                                                  │
│   1. Detect Terraform                  detect.py                 │
│   2. terraform init -backend=false     evaluate.py               │
│   3. terraform validate                evaluate.py               │
│   4. HCL → inventory                   inventory.py              │
│   5. Per-KSI evaluation                ksi/*/evaluator.py        │
│   6. Build evidence pack + SHA-256     evidence.py               │
│   7. POST /repos/{o}/{r}/check-runs    check_run.py ◄── NEW      │
│      (using workflow GITHUB_TOKEN)                               │
│   8. Upload artifact                   actions/upload-artifact   │
└──────────────────────────────────────────────────────────────────┘
```

The action's only outbound HTTP calls are to `api.github.com` (Check Run API) and `registry.terraform.io` (Terraform provider downloads during `init`). Both are documented at [`docs/network-calls.md`](docs/network-calls.md). Neither transits Boundera infrastructure.

## Migrating from `chukyjack/fedrampgpt-ksi-checker`

Three steps:

1. Uninstall the `fedrampgpt-ksi-checker` GitHub App from your org or repos.
2. Replace `uses: chukyjack/fedrampgpt-ksi-checker@v1` with `uses: Boundera/fedramp-20x-ksi-action@v1`.
3. Add `checks: write` to your workflow's `permissions:` block.

Output names from the original (`status`, `artifact_name`, `artifact_path`, `cna01_status`) are preserved as aliases through v0.x. Manifest schema carries both the new canonical ID (`canonical_id: KSI-MLA-EVC`) and the legacy ID (`id: KSI-MLA-05`) for parser compatibility.

Full guide: [`docs/migrating-from-fedrampgpt-ksi-checker.md`](docs/migrating-from-fedrampgpt-ksi-checker.md).

## FRMR provenance

This action evaluates against **FedRAMP Machine-Readable (FRMR) documentation v0.9.43-beta**, bundled at `data/frmr/FRMR.v0.9.43-beta.json`. The active version is pointed to by `data/frmr/CURRENT.txt`.

When FedRAMP publishes a new FRMR release, we drop in the new JSON, update `CURRENT.txt`, bump this action's minor version, and ship — typically within 72 hours of upstream publication. The `data/frmr/` directory carries the full release history so older versions of this action can be re-run reproducibly.

The FRMR document is a US Government work, public domain under 17 USC §105. See [`data/frmr/README.md`](data/frmr/README.md) for full provenance and the attribution notice.

## Status

**Alpha (v0.1.x).** The evaluation criteria, evidence pack format, and Check Run output are stable enough for daily use, but interfaces may change before v1.0. SemVer applies: any breaking change bumps the major. We update mappings within 72 hours of any FRMR change.

## Security

If you discover a vulnerability in the action's code, follow [`SECURITY.md`](SECURITY.md). Do not open a public issue.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). We accept PRs adding more evaluation criteria for `KSI-MLA-EVC` and `KSI-CNA-RNT`, bug reports against the action, and tests. Mappings for other KSI families belong in [`Boundera/fedramp-20x-toolkit`](https://github.com/Boundera/fedramp-20x-toolkit).

## Acknowledgments

- The [FedRAMP PMO](https://www.fedramp.gov/) for publishing the FRMR machine-readable documentation
- [NIST](https://pages.nist.gov/OSCAL/) for the OSCAL standard
- The original [`chukyjack/fedrampgpt-ksi-checker`](https://github.com/chukyjack/fedrampgpt-ksi-checker) for the Terraform-evaluation approach this action builds on

## License

MIT — see [`LICENSE`](LICENSE). The bundled FRMR document is a US Government work in the public domain and not subject to this license.
