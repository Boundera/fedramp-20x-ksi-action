"""GitHub Actions env adapter + main() entry (SPEC §2/§3)."""

from __future__ import annotations

import pytest

from fedramp_ksi.app import ConfigError, RunConfig, _config_from_env, main, run
from fedramp_ksi.model import AuthClass
from fedramp_ksi.reporters import RunMeta

from .conftest import FIXTURES


def test_config_from_env_parses_inputs(monkeypatch) -> None:
    monkeypatch.setenv("INPUT_PLAN_JSON", "plan.json")
    monkeypatch.setenv("INPUT_TARGET_CLASS", "b")
    monkeypatch.setenv("INPUT_FAIL_ON", "severity:high")
    monkeypatch.setenv("INPUT_KSI_IDS", "KSI-CNA-RNT, KSI-MLA-EVC")
    monkeypatch.setenv("INPUT_POST_CHECK_RUN", "false")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    cfg = _config_from_env()
    assert cfg.plan_json == "plan.json"
    assert cfg.target_class is AuthClass.B
    assert cfg.fail_on == "severity:high"
    assert cfg.ksi_ids == ("KSI-CNA-RNT", "KSI-MLA-EVC")
    assert cfg.post_check_run is False
    assert cfg.meta.repository == "acme/app"


def test_missing_input_raises() -> None:
    with pytest.raises(ConfigError):
        run(RunConfig(meta=RunMeta(generated_at="t")))


def test_main_writes_outputs_and_returns_exit_code(monkeypatch, tmp_path) -> None:
    out_file = tmp_path / "gh_output"
    summary_file = tmp_path / "step_summary"
    plan = FIXTURES / "aws" / "cna-rnt" / "violating.json"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("INPUT_PLAN_JSON", str(plan))
    monkeypatch.setenv("INPUT_KSI_IDS", "KSI-CNA-RNT")
    monkeypatch.setenv("INPUT_POST_CHECK_RUN", "false")
    monkeypatch.setenv("INPUT_COMMENT_ON_PR", "false")
    monkeypatch.setenv("INPUT_SARIF_OUTPUT", str(tmp_path / "out.sarif"))
    monkeypatch.setenv("INPUT_OUTPUT_DIR", "evidence")

    code = main()
    assert code == 1  # violating plan blocks

    outputs = out_file.read_text()
    assert "status=FAIL" in outputs
    assert "enforced_failures=2" in outputs
    assert "check_run_ids=[]" in outputs
    # multiline summary uses heredoc delimiter form
    assert "summary<<" in outputs
    assert "FedRAMP 20x KSI Gate" in summary_file.read_text()
