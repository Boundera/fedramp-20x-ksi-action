# data/frmr/

The FedRAMP Machine-Readable (FRMR) documentation files that this action evaluates against.

## Why this is bundled in the repo

Three reasons:

1. **Hermetic evaluations.** Customer CI runs don't need to reach out to fedramp.gov during a run. Network calls during evaluation are limited to `api.github.com` (Check Runs) and `registry.terraform.io` (Terraform providers).
2. **Reproducibility.** The action's evaluation result is bound to the exact FRMR snapshot in this directory. Re-running the same commit of this action against the same Terraform always produces the same evaluation, even if FedRAMP publishes a new FRMR version.
3. **Provenance for 3PAOs.** Evidence packs reference the specific FRMR version they were scored against. An auditor can see exactly which spec the evaluation used.

## Files

| File | Purpose |
|---|---|
| `CURRENT.txt` | One-line text file. Contains the filename of the active FRMR JSON. The action reads this at runtime to pick which version to load. |
| `FRMR.v0.9.43-beta.json` | The active FRMR documentation as of this release. Includes all 11 KSI families and 60 indicators. |

## Updating to a new FRMR release

When FedRAMP publishes a new FRMR version:

1. Drop the new JSON file into this directory using the naming pattern `FRMR.<version>.json` (e.g., `FRMR.v0.9.44-beta.json`).
2. Update `CURRENT.txt` to name the new file.
3. Bump the action's minor version (e.g., `0.1.3` → `0.2.0` if there are new indicators; `0.1.3` → `0.1.4` if it's a clarification-only release).
4. Re-run the tests to confirm no indicator IDs we evaluate against (`KSI-MLA-EVC`, `KSI-CNA-RNT`) were renamed or retired.
5. Update the README badge for FRMR version and `frmr_loader.py`'s logging defaults.

We keep the older JSON files in this directory so that anyone re-running an older tag of this action gets the FRMR snapshot it was built against.

## Provenance

The bundled FRMR document is published by the [FedRAMP Program Management Office](https://www.fedramp.gov/) and the General Services Administration. Canonical source: the FedRAMP PMO's published artifacts on fedramp.gov.

## License

FedRAMP documentation is a **work of the United States Government** and is **in the public domain pursuant to 17 USC §105**. It is not subject to the MIT license that covers the rest of this repository. No copyright is asserted in the FRMR content itself.

When redistributing portions of FRMR (for example, the indicator text and IDs that appear in this repository's mappings), attribution to the FedRAMP PMO is appreciated but not legally required.
