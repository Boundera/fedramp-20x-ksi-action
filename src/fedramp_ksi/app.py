"""Orchestrator — wires loader → engine → reporters → gate (SPEC §4).

``run(config)`` is pure-ish (no env, no process exit) so it is unit-testable.
``main()`` adapts GitHub Actions env/inputs to a :class:`RunConfig`, writes
outputs + the step summary, and returns the gate exit code.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .engine import Engine
from .gate import GateDecision, decide
from .loader import load_plan_file
from .loader.plan import load_plan
from .model import AuthClass, Provider, Severity
from .providers import build_graph
from .reporters import (
    RunMeta,
    RunReport,
    build_report,
    build_summary,
    post_check_run,
    upsert_pr_comment,
    write_evidence_pack,
)

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised for invalid/missing action configuration."""


@dataclass
class RunConfig:
    plan_json: str = ""
    terraform_dir: str = ""
    root_paths: tuple[str, ...] = (".",)
    providers: str = "auto"
    target_class: AuthClass = AuthClass.C
    fail_on: str = "enforce"
    min_severity: Severity = Severity.LOW
    waivers_file: str = ".fedramp-ksi-waivers.yml"
    baseline_file: str = ""
    today: str = ""  # ISO date for waiver-expiry evaluation; default = date.today()
    ksi_ids: tuple[str, ...] = ()
    output_dir: str = ".fedramp-evidence"
    sarif_output: str = "fedramp-ksi.sarif"
    post_check_run: bool = True
    comment_on_pr: bool = True
    workspace: str = "."
    trigger_event: str = "unknown"
    meta: RunMeta = field(default_factory=RunMeta)


@dataclass
class RunResult:
    report: RunReport
    artifact_paths: dict[str, Path]
    decision: GateDecision


def _providers_scope(cfg: RunConfig) -> tuple[Provider, ...] | None:
    if cfg.providers.strip().lower() in ("", "auto"):
        return None
    scope = []
    for tok in cfg.providers.split(","):
        tok = tok.strip().lower()
        if tok:
            scope.append(Provider(tok))
    return tuple(scope) or None


def _load_resources(cfg: RunConfig) -> list:
    if cfg.plan_json:
        return load_plan_file(cfg.plan_json)
    if cfg.terraform_dir:
        return _generate_plan_and_load(cfg)
    raise ConfigError(
        "Provide either 'plan_json' (a terraform show -json file) or 'terraform_dir'."
    )


def _generate_plan_and_load(cfg: RunConfig) -> list:
    """Fallback mode: run terraform in a dir and load the resulting plan JSON."""
    workdir = Path(cfg.workspace) / cfg.terraform_dir
    subprocess.run(["terraform", "init", "-input=false", "-no-color"], cwd=workdir, check=True)
    plan_bin = workdir / "fedramp.tfplan"
    subprocess.run(
        ["terraform", "plan", "-input=false", "-no-color", "-out", str(plan_bin)],
        cwd=workdir,
        check=True,
    )
    show = subprocess.run(
        ["terraform", "show", "-json", str(plan_bin)],
        cwd=workdir,
        check=True,
        capture_output=True,
        text=True,
    )
    return load_plan(json.loads(show.stdout))


def _build_transforms(config: RunConfig) -> list:
    """Assemble waiver + baseline finding transforms from the config."""
    from datetime import date

    from .waivers import baseline_transform, load_baseline, load_waivers, waiver_transform

    transforms: list = []
    waivers_path = Path(config.workspace) / config.waivers_file
    waivers = load_waivers(waivers_path)
    if waivers:
        today = date.fromisoformat(config.today) if config.today else date.today()
        transforms.append(waiver_transform(waivers, today))
    if config.baseline_file:
        baseline = load_baseline(Path(config.workspace) / config.baseline_file)
        if baseline:
            transforms.append(baseline_transform(baseline))
    return transforms


def run(config: RunConfig) -> RunResult:
    """Execute the full pipeline and return the result (no process exit)."""
    resources = _load_resources(config)
    scope = _providers_scope(config)
    graph = build_graph(resources, scope)

    engine = Engine(finding_transforms=_build_transforms(config))
    engine_result = engine.evaluate(
        graph,
        target_class=config.target_class,
        ksi_ids=list(config.ksi_ids) or None,
        providers=scope,
        trigger_event=config.trigger_event,
    )
    report = build_report(engine_result, meta=config.meta)
    paths = write_evidence_pack(report, config.output_dir)

    # Also emit SARIF at the configured path (for code-scanning upload).
    if config.sarif_output:
        sarif_out = Path(config.sarif_output)
        if not sarif_out.is_absolute():
            sarif_out = Path(config.workspace) / sarif_out
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(paths["sarif"].read_text(encoding="utf-8"), encoding="utf-8")
        paths["sarif_output"] = sarif_out

    decision = decide(report, config.fail_on)
    return RunResult(report=report, artifact_paths=paths, decision=decision)


# --- GitHub Actions adapter -------------------------------------------------


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _config_from_env() -> RunConfig:
    meta = RunMeta(
        repository=_env("GITHUB_REPOSITORY", "unknown/unknown"),
        commit_sha=_env("GITHUB_SHA", "0" * 40),
        trigger_event=_env("GITHUB_EVENT_NAME", "unknown"),
        actor=_env("GITHUB_ACTOR", "unknown"),
        run_url=(
            f"{_env('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{_env('GITHUB_REPOSITORY', 'x/y')}/actions/runs/{_env('GITHUB_RUN_ID', '0')}"
        ),
        action_version=_env("KSI_ACTION_VERSION", "0.2.0"),
        generated_at=_env("KSI_GENERATED_AT", ""),
    )
    workspace = _env("GITHUB_WORKSPACE", os.getcwd())
    return RunConfig(
        plan_json=_env("INPUT_PLAN_JSON"),
        terraform_dir=_env("INPUT_TERRAFORM_DIR"),
        root_paths=tuple(p.strip() for p in _env("INPUT_ROOT_PATHS", ".").split(",") if p.strip()),
        providers=_env("INPUT_PROVIDERS", "auto"),
        target_class=AuthClass(_env("INPUT_TARGET_CLASS", "C").upper()),
        fail_on=_env("INPUT_FAIL_ON", "enforce"),
        waivers_file=_env("INPUT_WAIVERS_FILE", ".fedramp-ksi-waivers.yml"),
        baseline_file=_env("INPUT_BASELINE_FILE", ""),
        today=_env("KSI_TODAY", ""),
        ksi_ids=tuple(x.strip() for x in _env("INPUT_KSI_IDS", "").split(",") if x.strip()),
        output_dir=str(Path(workspace) / _env("INPUT_OUTPUT_DIR", ".fedramp-evidence")),
        sarif_output=_env("INPUT_SARIF_OUTPUT", "fedramp-ksi.sarif"),
        post_check_run=_env("INPUT_POST_CHECK_RUN", "true").lower() in ("true", "1", "yes"),
        comment_on_pr=_env("INPUT_COMMENT_ON_PR", "true").lower() in ("true", "1", "yes"),
        workspace=workspace,
        trigger_event=_env("GITHUB_EVENT_NAME", "unknown"),
        meta=meta,
    )


def _set_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        if "\n" in value:
            import uuid

            delim = uuid.uuid4().hex
            f.write(f"{name}<<{delim}\n{value}\n{delim}\n")
        else:
            f.write(f"{name}={value}\n")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    config = _config_from_env()
    result = run(config)
    report, decision = result.report, result.decision

    _set_output("status", report.gate_status.value)
    _set_output("advisory_status", report.advisory_status.value)
    _set_output("findings_count", json.dumps(report.findings_by_severity()))
    _set_output("enforced_failures", str(report.enforced_failures))
    _set_output(
        "sarif_path", str(result.artifact_paths.get("sarif_output", result.artifact_paths["sarif"]))
    )
    _set_output("manifest_path", str(result.artifact_paths["manifest"]))
    _set_output("evidence_dir", config.output_dir)
    summary = build_summary(report)
    _set_output("summary", summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(summary)

    # Post a Check Run and/or refresh the PR comment (egress: GitHub API only).
    check_run_ids: list[int] = []
    if config.post_check_run:
        cid = post_check_run(report, decision)
        if cid is not None:
            check_run_ids.append(cid)
    _set_output("check_run_ids", json.dumps(check_run_ids))
    if config.comment_on_pr and config.trigger_event in ("pull_request", "pull_request_target"):
        upsert_pr_comment(report)

    print(f"Gate: {report.gate_status.value}  ({decision.reason})")
    if decision.blocked:
        print(f"::error::FedRAMP 20x KSI gate blocked the merge: {decision.reason}")
    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
