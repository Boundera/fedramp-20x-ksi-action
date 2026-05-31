"""Tests for action.src.check_run.

Covers status → conclusion mapping, summary markdown rendering, and the
POST request to api.github.com (mocked).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from action.src.check_run import (
    CheckRunError,
    build_summary_markdown,
    post_check_run,
    status_to_conclusion,
)


class TestStatusToConclusion:
    def test_pass(self) -> None:
        assert status_to_conclusion("PASS") == "success"

    def test_fail(self) -> None:
        assert status_to_conclusion("FAIL") == "failure"

    def test_error_is_neutral(self) -> None:
        assert status_to_conclusion("ERROR") == "neutral"

    def test_case_insensitive(self) -> None:
        assert status_to_conclusion("pass") == "success"
        assert status_to_conclusion("Fail") == "failure"

    def test_unknown_defaults_to_neutral(self) -> None:
        assert status_to_conclusion("WHATEVER") == "neutral"


class TestBuildSummaryMarkdown:
    @pytest.fixture
    def base_args(self) -> dict:
        return {
            "ksi_id": "KSI-MLA-EVC",
            "ksi_name": "Evaluating Configurations",
            "ksi_statement": "Persistently evaluate and test the configuration of machine-based information resources, especially infrastructure as code.",
            "status": "PASS",
            "criteria": [
                {
                    "id": "EVC-A",
                    "name": "Surface in scope",
                    "status": "PASS",
                    "reason": "Terraform .tf files detected",
                },
                {
                    "id": "EVC-B",
                    "name": "Machine-based evaluation",
                    "status": "PASS",
                    "reason": "terraform init + validate succeeded",
                },
            ],
            "repository": "Boundera/example",
            "commit_sha": "abc1234567890def",
            "trigger_event": "schedule",
        }

    def test_includes_ksi_id_and_name_in_heading(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "KSI-MLA-EVC: Evaluating Configurations" in md

    def test_includes_requirement_quote(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "> Persistently evaluate and test" in md

    def test_pass_status_emoji(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "✅" in md.split("\n")[0]

    def test_fail_status_emoji(self, base_args: dict) -> None:
        base_args["status"] = "FAIL"
        md = build_summary_markdown(**base_args)
        assert "❌" in md.split("\n")[0]

    def test_error_status_emoji(self, base_args: dict) -> None:
        base_args["status"] = "ERROR"
        md = build_summary_markdown(**base_args)
        assert "⚠️" in md.split("\n")[0]

    def test_criteria_table_rendered(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "| Criterion | Name | Status | Details |" in md
        assert "EVC-A" in md
        assert "EVC-B" in md

    def test_accepts_criteria_as_dict(self, base_args: dict) -> None:
        base_args["criteria"] = {
            "rule_a": {"id": "rule_a", "name": "Rule A", "status": "PASS", "reason": "ok"},
        }
        md = build_summary_markdown(**base_args)
        assert "Rule A" in md

    def test_scope_shows_repo_and_short_sha(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "Boundera/example" in md
        assert "abc1234" in md
        # full SHA should not appear (we trim to 7 chars)
        assert "abc1234567890def" not in md

    def test_artifact_link_when_provided(self, base_args: dict) -> None:
        md = build_summary_markdown(
            **base_args, artifact_name="evidence_ksi-mla-evc_abc1234_now.zip"
        )
        assert "evidence_ksi-mla-evc_abc1234_now.zip" in md

    def test_run_url_when_provided(self, base_args: dict) -> None:
        md = build_summary_markdown(
            **base_args,
            run_url="https://github.com/Boundera/example/actions/runs/123",
        )
        assert "https://github.com/Boundera/example/actions/runs/123" in md

    def test_extra_summary_lines(self, base_args: dict) -> None:
        md = build_summary_markdown(
            **base_args,
            extra_summary_lines=[
                "Security Groups Evaluated: 12",
                "Compliant: 11",
            ],
        )
        assert "Security Groups Evaluated: 12" in md
        assert "Compliant: 11" in md

    def test_footer_credits_action(self, base_args: dict) -> None:
        md = build_summary_markdown(**base_args)
        assert "Boundera/fedramp-20x-ksi-action" in md


class TestPostCheckRun:
    def _make_response(self, body: dict, status: int = 201) -> MagicMock:
        resp = MagicMock()
        resp.read.return_value = json.dumps(body).encode("utf-8")
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_raises_without_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with pytest.raises(CheckRunError, match="GITHUB_TOKEN"):
            post_check_run(
                ksi_id="KSI-MLA-EVC",
                ksi_name="Evaluating Configurations",
                status="PASS",
                summary_markdown="ok",
                repository="o/r",
                head_sha="abc1234",
            )

    def test_raises_without_repository(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "t")
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with pytest.raises(CheckRunError, match="GITHUB_REPOSITORY"):
            post_check_run(
                ksi_id="KSI-MLA-EVC",
                ksi_name="Evaluating Configurations",
                status="PASS",
                summary_markdown="ok",
                head_sha="abc1234",
            )

    def test_posts_correct_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
        captured: dict = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["headers"] = dict(req.header_items())
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return self._make_response({"id": 42})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            check_run_id = post_check_run(
                ksi_id="KSI-MLA-EVC",
                ksi_name="Evaluating Configurations",
                status="PASS",
                summary_markdown="hello",
                repository="Boundera/example",
                head_sha="abc1234567890",
            )

        assert check_run_id == 42
        assert captured["method"] == "POST"
        assert captured["url"] == "https://api.github.com/repos/Boundera/example/check-runs"
        assert captured["body"]["name"] == "KSI-MLA-EVC — Evaluating Configurations"
        assert captured["body"]["head_sha"] == "abc1234567890"
        assert captured["body"]["status"] == "completed"
        assert captured["body"]["conclusion"] == "success"
        # Confirm we're using a Bearer token, not Basic auth
        auth = captured["headers"].get(
            "Authorization", captured["headers"].get("authorization", "")
        )
        assert auth.startswith("Bearer ")
