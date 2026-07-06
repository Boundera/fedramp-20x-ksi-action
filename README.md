# FedRAMP 20x KSI Gate

A **preventive policy-as-code gate** for GitHub Actions. It evaluates a Terraform
**plan** against the FedRAMP 20x Key Security Indicators (Consolidated Rules
`2026.06.24.01`, 46 KSIs / 10 themes) and **blocks changes that would create
non-compliant cloud state** across AWS, Azure, and GCP — emitting SARIF, a signed
evidence pack (with a FedRAMP SDR record), and a commit Check Run. **No vendor
server in the loop.**

This is a control you put in your merge pipeline. It is not evidence theater:
every enforced check can fail a build on a real misconfiguration, and no `PASS`
is emitted for an outcome the plan cannot prove (see [honest status](#honest-status)).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quickstart

Generate a plan JSON, then run the gate (credential-free — it reads the plan, not your cloud):

```yaml
permissions: { contents: read, checks: write, pull-requests: write, security-events: write }
steps:
  - uses: actions/checkout@v4
  - run: terraform init && terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
  - uses: Boundera/fedramp-20x-ksi-action@v0
    with:
      plan_json: plan.json
      target_class: C          # A | B | C
```

A violating plan fails the step (non-zero exit) and posts a failing Check Run; a
clean plan passes. Upload `fedramp-ksi.sarif` with `github/codeql-action/upload-sarif`
to surface findings in code scanning.

## Why plan JSON, not raw HCL

The gate evaluates `terraform show -json` — the **resolved** plan — so modules,
`count`/`for_each`, variables, and locals are already expanded. A violation nested
inside a module is caught, not missed. Raw-HCL heuristics are prohibited for
enforced checks.

## Honest status

Statuses are `PASS · FAIL · PARTIAL · N/A · MANUAL · ERROR`, and a check may only
emit a status its evidence supports:

- **enforce** KSIs can `FAIL` a build; an enforce KSI never returns `PASS` without
  a violating fixture proving it *can* fail.
- **advisory** KSIs cap at `PARTIAL` for runtime-dependent outcomes.
- **manual** KSIs are recorded `MANUAL` with an external evidence pointer — never
  a fake `PASS`/`FAIL`.
- No Terraform / no matching resources ⇒ `N/A`, never `FAIL`.

See [docs/COVERAGE.md](docs/COVERAGE.md) for all 46 KSIs and their dispositions.

## Key inputs

| Input | Default | Description |
|---|---|---|
| `plan_json` | — | Path to `terraform show -json` output (primary, credential-free mode). |
| `terraform_dir` | — | Dir to run init+plan+show inside the action (needs read-only creds). |
| `target_class` | `C` | FedRAMP 20x class `A`\|`B`\|`C`. |
| `fail_on` | `enforce` | `enforce`, `severity:<level>`, or `none` (report-only). |
| `waivers_file` | `.fedramp-ksi-waivers.yml` | Expiring exceptions ([WAIVERS.md](docs/WAIVERS.md)). |
| `providers` | `auto` | `auto` or a subset of `aws,azure,gcp`. |
| `post_check_run` / `comment_on_pr` | `true` | Post a commit Check Run / refresh a PR comment. |

Outputs include `status`, `advisory_status`, `findings_count`, `enforced_failures`,
`sarif_path`, `manifest_path`, and `summary`. See [action.yml](action.yml) for the full list.

## Evidence

Each run writes an evidence pack to `output_dir` (default `.fedramp-evidence/`):

- `manifest.json` — deterministic; every KSI disposition/status, findings, applied
  waivers, and the pinned ruleset version + SHA-256.
- `fedramp-ksi.sarif` — SARIF 2.1.0 for code scanning.
- `sdr.json` — a FedRAMP Security Decision Record `keySecurityIndicators` document.
- `CHECKSUMS.sha256` — tamper-evidence over the pack.

## Docs

- [COVERAGE.md](docs/COVERAGE.md) — the 46 KSIs + dispositions (generated).
- [WAIVERS.md](docs/WAIVERS.md) — waivers & baseline.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to add a KSI.
- [SECURITY.md](SECURITY.md) · [docs/DECISIONS.md](docs/DECISIONS.md).

## License

MIT. FedRAMP documentation is a US Government work in the public domain (17 USC §105).
