# Contributing to fedramp-20x-ksi-action

Thanks for considering a contribution. This document covers what we accept, how to propose changes, and what to expect in review.

## Adding a KSI (the extensible path)

Adding coverage is **a registry entry + an evaluator module + fixtures** — no
edits to the orchestrator or dispatcher (evaluators and provider adapters are
auto-discovered). Test-first:

1. **Fixtures first.** Add `tests/fixtures/<provider>/<ksi-lower>/compliant.json`
   and `violating.json` — real `terraform show -json` output. For an **enforce**
   KSI both are required; the meta-test in `tests/unit/test_enforce_counterexamples.py`
   fails if a violating fixture does not produce `FAIL`. *A check that cannot
   fail is not a check.*
2. **Adapter (if needed).** Map the provider resource type(s) into a normalized
   model type in `src/fedramp_ksi/providers/<cloud>/*.py` with `@adapter(...)`.
   Reuse an existing normalized type where possible.
3. **Evaluator.** Add `src/fedramp_ksi/ksi/<ksi>.py` with an `@register_evaluator("KSI-...")`
   function returning `Finding`s. Emit a `PASS` finding when in-scope resources
   are compliant; return `[]` (⇒ `N/A`) when there are no in-scope resources.
   Respect the [honest-status rules](docs/DECISIONS.md): enforce ≠ `PARTIAL`,
   manual ≠ `PASS`/`FAIL`.
4. **Regenerate docs.** `python tools/gen_coverage_doc.py` and commit
   `docs/COVERAGE.md` (a test asserts it is in sync).
5. **Run everything.** `ruff check . && ruff format --check . && pytest` — the
   engine coverage gate is ≥90%.

The KSI's disposition (enforce/advisory/manual) already lives in
`src/fedramp_ksi/registry.py`; if you believe a disposition is wrong, change it
there and update the SPEC/`docs/DECISIONS.md` rationale — the completeness test
enforces the per-class totals.


## What we accept

- **Additional evaluation criteria** for `KSI-MLA-EVC` (Evaluating Configurations) and `KSI-CNA-RNT` (Restricting Network Traffic). For example, additional Terraform patterns to detect, additional drift checks, or new evidence sources within the existing two KSIs.
- **Bug reports and fixes** for the action's code, particularly around `check_run.py` (the new Check Run posting module) and `frmr_loader.py`.
- **Tests** — OSCAL/JSON manifest edge cases, fixture variants, additional pass/fail scenarios.
- **Documentation improvements** — typos, clarifications, better examples.
- **FRMR version bumps** — when FedRAMP publishes a new FRMR release, PRs that drop in the new JSON and update `data/frmr/CURRENT.txt` are welcome.

We do **not** currently accept:

- Mappings or evaluators for KSI families this action does not cover (AFR, CMT, CNA-other, CED, IAM, INR, MLA-other, PIY, RPL, SVC, SCR). Those belong in [`Boundera/fedramp-20x-toolkit`](https://github.com/Boundera/fedramp-20x-toolkit) (for KSI mappings) or in Boundera's commercial product (for runtime evidence collection).
- Re-introduction of a vendor-hosted backend / GitHub App / webhook receiver. The no-server architecture is intentional — see [`docs/architecture-no-server.md`](docs/architecture-no-server.md).
- Non-Terraform IaC support (Pulumi, CloudFormation, Bicep). Open a Discussion before doing this work; it's likely v0.2 scope but not v0.1.x.

If unsure whether something fits, open a [GitHub Discussion](https://github.com/Boundera/fedramp-20x-ksi-action/discussions) before doing the work.

## Before you start

1. Search existing [Issues](https://github.com/Boundera/fedramp-20x-ksi-action/issues) and [Discussions](https://github.com/Boundera/fedramp-20x-ksi-action/discussions) to avoid duplicate work.
2. For non-trivial changes, open a Discussion first. We'll respond within 3 business days.

## Development setup

```bash
git clone https://github.com/Boundera/fedramp-20x-ksi-action
cd fedramp-20x-ksi-action

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

To run the action end-to-end against a local Terraform fixture:

```bash
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

`INPUT_POST_CHECK_RUN=false` skips the Check Run API call, so you don't need a real GitHub repo.

## Pull request checklist

Before opening a PR:

- [ ] Tests pass locally (`pytest`)
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy action/ shared/` passes
- [ ] If you added or changed an evaluator, you added a corresponding test fixture
- [ ] If you changed the manifest schema, you updated `docs/evidence-pack-schema.md`
- [ ] If your change is user-visible, the README reflects it
- [ ] Commit messages are descriptive (we use [Conventional Commits](https://www.conventionalcommits.org/))
- [ ] PR description references the issue or discussion it addresses

## Code style

- Python: `ruff` for linting and formatting (config in `pyproject.toml`)
- 100-character line length (matches `ruff` config)
- `from __future__ import annotations` at the top of new modules
- Public API: docstrings in Google style

## Review process

- A maintainer responds within 3 business days
- Expect 1–2 rounds of review
- Once approved, a maintainer merges with a squash commit

## License

By contributing, you agree your contributions are licensed under the MIT License.

## Questions

Open a [Discussion](https://github.com/Boundera/fedramp-20x-ksi-action/discussions) or email `oss@boundera.io`.
