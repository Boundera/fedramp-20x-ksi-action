# Porting from chukyjack/fedrampgpt-ksi-checker

The new `Boundera/fedramp-20x-ksi-action` shares most of its evaluation logic with the original `chukyjack/fedrampgpt-ksi-checker` repo. Rather than re-implement detection, HCL parsing, evaluator logic, evidence pack building, and tests from scratch, we **port** the originals — with surgical changes.

This guide is the developer playbook for that port. Run through it once, end to end, and the new repo will have a working `v0.1.0`.

## What stays the same

Everything in `action/src/` from the original, except for module renames driven by the KSI ID migration:

| Original module | New location | Change |
|---|---|---|
| `action/src/main.py` | same path | Minor: wire in `check_run.py` + `frmr_loader.py`, set new output names. |
| `action/src/detect.py` | same path | None. |
| `action/src/evaluate.py` | same path | None. |
| `action/src/inventory.py` | same path | None. |
| `action/src/evidence.py` | same path | None (artifact naming pattern preserved). |
| `action/src/ksi/cna/cna01/` | `action/src/ksi/cna/rnt/` | **Rename directory.** Update imports. |
| `action/src/ksi/cna/shared/` | same path | None. |
| `shared/schemas.py` | same path | None. |
| `shared/constants.py` | same path | Add `KSI_MLA_EVC_CANONICAL_ID` and `KSI_MLA_05_FKA` constants. |
| `shared/constants_cna.py` | same path | Add `KSI_CNA_RNT_CANONICAL_ID`. Keep `CNA01_KSI_ID` for backwards compat. |

## What gets deleted

Everything in `app/`, plus the deploy artifacts:

```
DELETE: app/                       # FastAPI webhook receiver — replaced by check_run.py
DELETE: Procfile                   # Railway/Heroku deploy — not needed
DELETE: railway.json               # Railway config — not needed
DELETE: DEPLOYMENT.md              # Replace with a short "ops" appendix in README
```

These corresponding entries also go from `requirements.txt` and `pyproject.toml`:

```
fastapi
uvicorn[standard]
gunicorn
httpx
PyJWT
cryptography           # only the JWT-related usage was for the App; keep if other modules need it
pydantic-settings
```

## What's new (already in this repo)

These files are new, written by Boundera, and live in this repo (no port needed):

- `action/src/check_run.py` — posts Check Runs from inside the action using `GITHUB_TOKEN`. **The architectural centerpiece.**
- `action/src/frmr_loader.py` — loads the bundled FRMR JSON, resolves indicator IDs (current + fka).
- `data/frmr/CURRENT.txt`
- `data/frmr/FRMR.v0.9.43-beta.json`
- `data/frmr/README.md`
- `README.md`, `LICENSE`, `CONTRIBUTING.md`, etc. — repo foundation
- `action.yml` — composite action manifest with the new inputs/outputs
- `pyproject.toml`, `requirements.txt` — slim dependency set
- `docs/architecture-no-server.md` (TBD)
- `docs/migrating-from-fedrampgpt-ksi-checker.md` (TBD)
- `docs/network-calls.md` (TBD)

## Step-by-step port

### 1. Bring over the modules that stay the same

From your local clone of `chukyjack/fedrampgpt-ksi-checker`, copy these files into this repo at the same paths:

```bash
ORIGINAL=~/code/fedrampgpt-ksi-checker          # adjust to your local path
NEW=~/code/fedramp-20x-ksi-action

cp $ORIGINAL/action/src/detect.py     $NEW/action/src/detect.py
cp $ORIGINAL/action/src/evaluate.py   $NEW/action/src/evaluate.py
cp $ORIGINAL/action/src/inventory.py  $NEW/action/src/inventory.py
cp $ORIGINAL/action/src/evidence.py   $NEW/action/src/evidence.py
cp -R $ORIGINAL/action/src/ksi/cna/shared $NEW/action/src/ksi/cna/shared
cp -R $ORIGINAL/shared $NEW/shared
cp -R $ORIGINAL/tests $NEW/tests
```

### 2. Rename CNA-01 → CNA-RNT

```bash
mkdir -p $NEW/action/src/ksi/cna/rnt
cp -R $ORIGINAL/action/src/ksi/cna/cna01/* $NEW/action/src/ksi/cna/rnt/
```

Then fix imports throughout the codebase:

```bash
cd $NEW
grep -rl 'ksi.cna.cna01' --include='*.py' | xargs sed -i.bak 's|ksi\.cna\.cna01|ksi.cna.rnt|g'
grep -rl 'KSI-CNA-01' --include='*.py' | xargs sed -i.bak 's|KSI-CNA-01|KSI-CNA-RNT|g'
grep -rl 'cna01_' --include='*.py' | xargs sed -i.bak 's|cna01_|cna_rnt_|g'
find . -name '*.bak' -delete
```

Note: the **manifest schema** keeps `KSI-CNA-01` as a `fka` field so customer SSPs that reference the legacy ID still resolve. The Python code uses the canonical ID; the on-disk evidence carries both.

### 3. Rename KSI-MLA-05 → KSI-MLA-EVC in user-facing strings

The Python code in the original used `KSI-MLA-05` as a constant in many places. Update each to `KSI-MLA-EVC` and carry the legacy ID as a `fka` field in the emitted manifest. Touchpoints:

```
action/src/main.py                 # output names, log strings
action/src/evidence.py             # manifest `id` becomes `canonical_id`; new `id` = fka
shared/constants.py                # rename KSI_REQUIREMENT_TEXT to align with EVC name
action/src/ksi/mla/...             # may need to rename module path mla05 → mla/evc
tests/                             # fixture filenames and assertion strings
```

A workable sed pass:

```bash
cd $NEW
grep -rl 'KSI-MLA-05' --include='*.py' | xargs sed -i.bak 's|KSI-MLA-05|KSI-MLA-EVC|g'
grep -rl 'ksi-mla-05' --include='*' | xargs sed -i.bak 's|ksi-mla-05|ksi-mla-evc|g'
grep -rl 'mla05' --include='*.py' | xargs sed -i.bak 's|mla05|mla_evc|g'
find . -name '*.bak' -delete
```

### 4. Wire in `check_run.py` from `main.py`

After the evidence pack is built for each KSI and `INPUT_POST_CHECK_RUN` is `true`, call:

```python
from action.src.check_run import post_check_run, build_summary_markdown
from action.src.frmr_loader import load_frmr

frmr = load_frmr()
indicator = frmr.resolve(ksi_id)   # accepts new or fka ID

summary_md = build_summary_markdown(
    ksi_id=indicator.id,
    ksi_name=indicator.name,
    ksi_statement=indicator.statement,
    status=status,
    criteria=manifest["criteria"],
    repository=ctx["repository"],
    commit_sha=ctx["commit_sha"],
    trigger_event=ctx["trigger_event"],
    artifact_name=artifact_name,
    run_url=ctx["workflow_run_url"],
)

check_run_id = post_check_run(
    ksi_id=indicator.id,
    ksi_name=indicator.name,
    status=status,
    summary_markdown=summary_md,
)
```

That single function call replaces the entire `app/` directory.

### 5. Update emitted manifest schema

In `evidence.py` and any per-KSI `evidence.py`, ensure the emitted `evaluation_manifest.json` carries:

```json
{
  "id": "KSI-MLA-05",
  "canonical_id": "KSI-MLA-EVC",
  "name": "Evaluating Configurations",
  "family": "MLA",
  "frmr_version": "0.9.43-beta",
  ...
}
```

`id` is the legacy ID for parser compatibility with the original action; `canonical_id` is the current mnemonic.

### 6. Update tests

The renames will break a number of assertions. Run `pytest` and fix the assertions methodically. The patterns that need updating:

- Strings: `"KSI-MLA-05"` → `"KSI-MLA-EVC"` (often expected at top level of the manifest), keep the FKA pattern.
- Artifact name patterns: `evidence_ksi-mla-05_*` → `evidence_ksi-mla-evc_*`.
- New tests to add: see `tests/test_check_run.py` (mocks `urllib.request.urlopen` and asserts the right payload is sent).

### 7. Verify the action.yml inputs/outputs match

The `action.yml` in this new repo expects specific output names from the Python entry point:

```
status, mla_evc_status, cna_rnt_status, evidence_dir,
mla_evc_artifact_name, cna_rnt_artifact_name,
artifact_names, check_run_ids, summary
```

Make sure `main.py` calls `set_output(...)` for each.

### 8. Run the smoke test

```bash
cd $NEW
pip install -e ".[dev]"
pytest -v

# End-to-end against the bundled pass fixture:
INPUT_ROOT_PATHS=tests/fixtures/pass-repo \
INPUT_KSI_IDS="KSI-MLA-EVC,KSI-CNA-RNT" \
INPUT_POST_CHECK_RUN=false \
GITHUB_REPOSITORY=test/repo \
GITHUB_SHA=abc1234567890 \
GITHUB_WORKFLOW=Test \
GITHUB_RUN_ID=12345 \
GITHUB_EVENT_NAME=schedule \
GITHUB_ACTOR=test-user \
GITHUB_WORKSPACE=$(pwd)/tests/fixtures/pass-repo \
FRMR_BUNDLE_DIR=$(pwd)/data/frmr \
python action/src/main.py
```

Expected: `mla_evc_status=PASS`, `cna_rnt_status=PASS`, evidence packs created.

### 9. Push and tag

```bash
git add .
git commit -m "v0.1.0: port from chukyjack/fedrampgpt-ksi-checker; eliminate vendor server"
git push -u origin main
git tag v0.1.0
git tag v1
git push --tags
```

### 10. Marketplace listing

Once `v1` exists, go to the repo's "Releases" page in GitHub, edit the `v1` release, and toggle "Publish this Action to the GitHub Marketplace." Fill in:

- **Primary category:** Security
- **Description:** "Evaluate Terraform IaC against FedRAMP 20x KSIs. No vendor server — runs entirely in your runner."
- **Icon:** shield, blue (matches `action.yml`).

Marketplace listings typically go live within 24 hours.

## Time estimate

A focused engineer with the original repo cloned locally can complete steps 1–9 in ~4 hours. The hardest part is the test fixture/assertion updates (~2 of those 4 hours). Marketplace listing is another 30 minutes.
