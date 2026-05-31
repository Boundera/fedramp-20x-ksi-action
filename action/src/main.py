#!/usr/bin/env python3
"""Main entry point for Boundera/fedramp-20x-ksi-action.

Differs from the original chukyjack/fedrampgpt-ksi-checker main.py in three
material ways:

1. Loads the bundled FRMR document via action.src.frmr_loader and resolves
   user-supplied KSI IDs against it. Auto-maps legacy numeric IDs (e.g.,
   KSI-MLA-05) to current mnemonic IDs (KSI-MLA-EVC) via the `fka` field.

2. Posts GitHub Check Runs directly to api.github.com using GITHUB_TOKEN —
   the action no longer relies on a vendor-hosted GitHub App / webhook
   receiver. See action.src.check_run.

3. Emits manifests that carry both the canonical mnemonic ID and the legacy
   numeric ID so downstream parsers built against either generation of the
   action keep working unchanged.

This module orchestrates per-KSI evaluation. The actual evaluation logic
lives in:

  - detect.py / evaluate.py / inventory.py / evidence.py (KSI-MLA-EVC)
  - action.src.ksi.cna.rnt.evaluator (KSI-CNA-RNT)
  - action.src.ksi.cna.shared.network_inventory

These are ported from the original repo (see docs/PORTING-FROM-ORIGINAL.md).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path so `action.src.*` and `shared.*` resolve when invoked
# via `python action/src/main.py` from the action's checkout directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# GitHub Actions helpers
# -----------------------------------------------------------------------------


def get_github_context() -> dict[str, str]:
    """Read the GitHub Actions environment into a dict."""
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    run_id = os.environ.get("GITHUB_RUN_ID", "0")
    return {
        "server_url": server_url,
        "repository": repository,
        "commit_sha": os.environ.get("GITHUB_SHA", "0" * 40),
        "workflow_name": os.environ.get("GITHUB_WORKFLOW", "FedRAMP KSI"),
        "workflow_run_id": run_id,
        "workflow_run_url": f"{server_url}/{repository}/actions/runs/{run_id}",
        "trigger_event": os.environ.get("GITHUB_EVENT_NAME", "unknown"),
        "actor": os.environ.get("GITHUB_ACTOR", "unknown"),
        "workspace": os.environ.get("GITHUB_WORKSPACE", os.getcwd()),
    }


def set_output(name: str, value: str) -> None:
    """Write a GitHub Actions output via $GITHUB_OUTPUT."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        # Fallback for local invocation: print to stderr so it's visible
        # but doesn't get captured as an action output.
        print(f"(no GITHUB_OUTPUT) {name}={value[:120]}", file=sys.stderr)
        return
    with open(output_file, "a", encoding="utf-8") as f:
        if "\n" in value:
            import uuid

            delim = uuid.uuid4().hex
            f.write(f"{name}<<{delim}\n{value}\n{delim}\n")
        else:
            f.write(f"{name}={value}\n")


def log_group(title: str) -> None:
    print(f"::group::{title}")


def log_group_end() -> None:
    print("::endgroup::")


def log_warning(message: str) -> None:
    print(f"::warning::{message}")


def log_error(message: str) -> None:
    print(f"::error::{message}")


# -----------------------------------------------------------------------------
# Per-KSI evaluation dispatch
# -----------------------------------------------------------------------------


def evaluate_mla_evc(
    workspace: Path, output_dir: Path, ctx: dict[str, str], detection, terraform_version: str | None
) -> dict:
    """Evaluate KSI-MLA-EVC (Evaluating Configurations).

    Uses the top-level evaluate/inventory/evidence modules ported from the
    original repo. Wires the result into the new manifest schema.
    """
    from action.src.detect import get_tf_root_paths  # noqa: PLC0415
    from action.src.evaluate import evaluate_terraform  # noqa: PLC0415
    from action.src.evidence import build_evidence_pack  # noqa: PLC0415
    from action.src.inventory import generate_inventory  # noqa: PLC0415

    eval_result = None
    inventory = None

    if detection.detected:
        log_group("KSI-MLA-EVC: Terraform evaluation")
        tf_roots = get_tf_root_paths(detection)
        for tf_root in tf_roots:
            eval_path = workspace / tf_root if tf_root != "." else workspace
            print(f"Evaluating Terraform at: {eval_path}")
            eval_result = evaluate_terraform(eval_path)
            print(f"  init={eval_result.init_success} validate={eval_result.validate_success}")
            if eval_result.error_message:
                log_error(eval_result.error_message)
        log_group_end()

        log_group("KSI-MLA-EVC: Inventory")
        inventory = generate_inventory(workspace, detection.tf_paths)
        print(f"Resources: {inventory.resources.total_count}")
        log_group_end()

    log_group("KSI-MLA-EVC: Evidence pack")
    zip_path, artifact_name, status = build_evidence_pack(
        output_dir=output_dir,
        detection=detection,
        inventory=inventory,
        eval_result=eval_result,
        repository=ctx["repository"],
        commit_sha=ctx["commit_sha"],
        workflow_name=ctx["workflow_name"],
        workflow_run_id=ctx["workflow_run_id"],
        workflow_run_url=ctx["workflow_run_url"],
        trigger_event=ctx["trigger_event"],
        actor=ctx["actor"],
        terraform_version=terraform_version,
    )
    log_group_end()

    # Read the just-written manifest to attach to the Check Run summary.
    manifest_path = output_dir / "evidence" / "ksi-mla-evc" / "evaluation_manifest.json"
    if not manifest_path.exists():
        # Fallback for ports that haven't been renamed yet.
        manifest_path = output_dir / "evidence" / "ksi-mla-05" / "evaluation_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    return {
        "canonical_id": "KSI-MLA-EVC",
        "fka": "KSI-MLA-05",
        "name": "Evaluating Configurations",
        "status": status.value if hasattr(status, "value") else str(status),
        "artifact_name": artifact_name,
        "zip_path": str(zip_path),
        "manifest": manifest,
    }


def evaluate_cna_rnt(
    workspace: Path, output_dir: Path, ctx: dict[str, str], detection, terraform_version: str | None
) -> dict:
    """Evaluate KSI-CNA-RNT (Restricting Network Traffic)."""
    from action.src.ksi.cna.rnt.evaluator import evaluate_cna_rnt as _evaluate  # noqa: PLC0415
    from action.src.ksi.cna.rnt.evidence import build_cna_rnt_evidence_pack  # noqa: PLC0415
    from action.src.ksi.cna.shared.network_inventory import (
        extract_network_inventory,  # noqa: PLC0415
    )

    log_group("KSI-CNA-RNT: Network inventory")
    net_inv = extract_network_inventory(workspace, detection.tf_paths)
    print(f"Security groups: {len(net_inv.security_groups)}")
    print(f"VPCs:            {len(net_inv.vpcs)}")
    log_group_end()

    log_group("KSI-CNA-RNT: Criteria evaluation")
    criteria, summary = _evaluate(net_inv, ctx["trigger_event"])
    log_group_end()

    log_group("KSI-CNA-RNT: Evidence pack")
    zip_path, artifact_name, status = build_cna_rnt_evidence_pack(
        output_dir=output_dir,
        inventory=net_inv,
        criteria=criteria,
        summary=summary,
        repository=ctx["repository"],
        commit_sha=ctx["commit_sha"],
        trigger_event=ctx["trigger_event"],
        tf_paths=detection.tf_paths,
        terraform_version=terraform_version,
    )
    log_group_end()

    manifest_path = output_dir / "evidence" / "ksi-cna-rnt" / "evaluation_manifest.json"
    if not manifest_path.exists():
        manifest_path = output_dir / "evidence" / "ksi-cna-01" / "evaluation_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    return {
        "canonical_id": "KSI-CNA-RNT",
        "fka": "KSI-CNA-01",
        "name": "Restricting Network Traffic",
        "status": str(status),
        "artifact_name": artifact_name,
        "zip_path": str(zip_path),
        "manifest": manifest,
    }


# -----------------------------------------------------------------------------
# Combined results
# -----------------------------------------------------------------------------


def write_combined_results(output_dir: Path, results: list[dict], ctx: dict[str, str]) -> None:
    """Write the combined results.json that the action uploads as an artifact."""
    payload = {
        "schema_version": "2.0",  # bumped from original (which was 1.0)
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "trigger_event": ctx["trigger_event"],
        "repository": ctx["repository"],
        "commit_sha": ctx["commit_sha"],
        "action_repo": "Boundera/fedramp-20x-ksi-action",
        "frmr_version": _frmr_version(),
        "ksi_results": [
            {
                "canonical_id": r["canonical_id"],
                "fka": r.get("fka"),
                "name": r["name"],
                "status": r["status"],
                "evidence_path": f"evidence/{r['canonical_id'].lower()}/evaluation_manifest.json",
                "artifact_name": r["artifact_name"],
            }
            for r in results
        ],
    }
    (output_dir / "results.json").write_text(json.dumps(payload, indent=2))


def _frmr_version() -> str:
    try:
        from action.src.frmr_loader import load_frmr  # noqa: PLC0415

        return load_frmr().version
    except Exception:
        return "unknown"


# -----------------------------------------------------------------------------
# Check Run posting
# -----------------------------------------------------------------------------


def post_check_runs_for(results: list[dict], ctx: dict[str, str]) -> list[int]:
    """Post a Check Run on the commit for each evaluated KSI.

    Returns the list of created Check Run IDs.
    """
    from action.src.check_run import (  # noqa: PLC0415
        CheckRunError,
        build_summary_markdown,
        post_check_run,
    )
    from action.src.frmr_loader import load_frmr  # noqa: PLC0415

    if os.environ.get("INPUT_POST_CHECK_RUN", "true").lower() not in ("true", "1", "yes"):
        logger.info("post_check_run=false; skipping Check Run posting.")
        return []

    if not os.environ.get("GITHUB_TOKEN"):
        log_error(
            "post_check_run is enabled but GITHUB_TOKEN is unavailable. "
            "Add 'permissions: { checks: write }' to your workflow."
        )
        return []

    frmr = load_frmr()
    created: list[int] = []

    for r in results:
        try:
            ind = frmr.resolve(r["canonical_id"])
        except KeyError:
            log_warning(f"Indicator {r['canonical_id']} not in FRMR; skipping Check Run.")
            continue

        summary_md = build_summary_markdown(
            ksi_id=ind.id,
            ksi_name=ind.name,
            ksi_statement=ind.statement,
            status=r["status"],
            criteria=r["manifest"].get("criteria", []),
            repository=ctx["repository"],
            commit_sha=ctx["commit_sha"],
            trigger_event=ctx["trigger_event"],
            artifact_name=r.get("artifact_name"),
            run_url=ctx["workflow_run_url"],
        )

        try:
            check_run_id = post_check_run(
                ksi_id=ind.id,
                ksi_name=ind.name,
                status=r["status"],
                summary_markdown=summary_md,
            )
            created.append(check_run_id)
        except CheckRunError as exc:
            log_error(f"Failed to post Check Run for {ind.id}: {exc}")

    return created


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------


def main() -> int:
    """Action entry point. Always returns 0 so the workflow can upload artifacts."""
    from action.src.detect import scan_for_terraform  # noqa: PLC0415
    from action.src.evaluate import get_terraform_version  # noqa: PLC0415
    from action.src.frmr_loader import resolve_requested_ksi_ids  # noqa: PLC0415

    [p.strip() for p in os.environ.get("INPUT_ROOT_PATHS", ".").split(",") if p.strip()]
    requested_ksi_ids = [
        x.strip()
        for x in os.environ.get("INPUT_KSI_IDS", "KSI-MLA-EVC,KSI-CNA-RNT").split(",")
        if x.strip()
    ]

    ctx = get_github_context()
    workspace = Path(ctx["workspace"])
    output_dir = workspace / ".fedramp-evidence"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("Boundera/fedramp-20x-ksi-action")
    print("=" * 70)
    print(f"Repository: {ctx['repository']}")
    print(f"Commit:     {ctx['commit_sha'][:7]}")
    print(f"Trigger:    {ctx['trigger_event']}")
    print(f"KSI IDs:    {requested_ksi_ids}")

    # Resolve requested KSI IDs (auto-maps legacy IDs via fka).
    try:
        resolved = resolve_requested_ksi_ids(requested_ksi_ids)
    except KeyError as exc:
        log_error(f"Unknown KSI ID: {exc}")
        return 0
    print(f"Resolved:   {[ind.id for ind in resolved]}")

    # Detect Terraform once; per-KSI evaluators reuse the result.
    log_group("Terraform detection")
    detection = scan_for_terraform(workspace)
    print(f"Detected:  {detection.detected}")
    print(f"Files:     {detection.tf_file_count}")
    log_group_end()

    terraform_version = get_terraform_version() if detection.detected else None

    # Dispatch evaluation per requested KSI.
    results: list[dict] = []
    for ind in resolved:
        if ind.id == "KSI-MLA-EVC":
            results.append(
                evaluate_mla_evc(workspace, output_dir, ctx, detection, terraform_version)
            )
        elif ind.id == "KSI-CNA-RNT":
            results.append(
                evaluate_cna_rnt(workspace, output_dir, ctx, detection, terraform_version)
            )
        else:
            log_warning(
                f"Indicator {ind.id} is in FRMR but not yet implemented by this action. "
                f"v0.1.0 supports KSI-MLA-EVC and KSI-CNA-RNT only. Skipping."
            )

    # Combined results.json (uploaded as a separate artifact for quick scanning).
    write_combined_results(output_dir, results, ctx)

    # Worst-status across KSIs.
    worst = "PASS"
    for r in results:
        s = (r["status"] or "ERROR").upper()
        if s == "FAIL" and worst != "ERROR":
            worst = "FAIL"
        elif s == "ERROR":
            worst = "ERROR"

    # Action outputs.
    set_output("status", worst)
    for r in results:
        key_canonical = r["canonical_id"].lower().replace("-", "_").replace("ksi_", "")
        set_output(f"{key_canonical}_status", r["status"])
        set_output(f"{key_canonical}_artifact_name", r["artifact_name"])
    set_output("evidence_dir", str(output_dir / "evidence"))
    set_output("artifact_names", json.dumps([r["artifact_name"] for r in results]))

    # Post Check Runs.
    check_run_ids = post_check_runs_for(results, ctx)
    set_output("check_run_ids", json.dumps(check_run_ids))

    # Markdown summary written to $GITHUB_STEP_SUMMARY.
    summary = _build_workflow_summary(results, ctx, check_run_ids)
    set_output("summary", summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(summary)

    print()
    print("=" * 70)
    print("Final results")
    for r in results:
        print(f"  {r['canonical_id']:<14}  {r['status']}")
    print(f"  Worst:        {worst}")
    print(f"  Check Runs:   {len(check_run_ids)}")
    print("=" * 70)
    return 0


def _build_workflow_summary(
    results: list[dict], ctx: dict[str, str], check_run_ids: list[int]
) -> str:
    lines = [
        "## Boundera/fedramp-20x-ksi-action — Results",
        "",
        f"**Repository:** `{ctx['repository']}`  ",
        f"**Commit:** `{ctx['commit_sha'][:7]}`  ",
        f"**Trigger:** `{ctx['trigger_event']}`  ",
        f"**FRMR version:** `{_frmr_version()}`",
        "",
        "| KSI | Status | Evidence artifact |",
        "|---|---|---|",
    ]
    for r in results:
        emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(r["status"].upper(), "❓")
        lines.append(
            f"| **{r['canonical_id']}** {r['name']} "
            f"_(fka {r.get('fka', '—')})_ | {emoji} {r['status']} | `{r['artifact_name']}` |"
        )
    lines.append("")
    if check_run_ids:
        lines.append(f"Posted {len(check_run_ids)} Check Run(s) on the commit.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
