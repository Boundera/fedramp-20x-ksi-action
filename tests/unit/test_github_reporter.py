"""GitHub Check Run + PR comment reporters — mocked HTTP (SPEC §2, §13)."""

from __future__ import annotations

import json

from fedramp_ksi.engine import Engine
from fedramp_ksi.gate import decide
from fedramp_ksi.loader import load_plan_file
from fedramp_ksi.model import AuthClass
from fedramp_ksi.providers import build_graph
from fedramp_ksi.reporters import RunMeta, build_report, post_check_run, upsert_pr_comment
from fedramp_ksi.reporters import github as gh

from .conftest import fixture


def _report():
    resources = load_plan_file(fixture("aws", "cna-rnt", "violating.json"))
    er = Engine().evaluate(
        build_graph(resources), ksi_ids=["KSI-CNA-RNT"], target_class=AuthClass.C
    )
    return build_report(er, meta=RunMeta(commit_sha="a" * 40, generated_at="t"))


class _FakeResp:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_check_run_skipped_without_token(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    assert post_check_run(_report(), decide(_report(), "enforce")) is None


def test_check_run_posts_with_token(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(req, timeout=30):
        captured["url"] = req.full_url
        captured["method"] = req.method
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp({"id": 4242})

    monkeypatch.setattr(gh.urllib.request, "urlopen", fake_urlopen)
    cid = post_check_run(
        _report(), decide(_report(), "enforce"), token="t", repository="o/r", head_sha="a" * 40
    )
    assert cid == 4242
    assert captured["url"] == "https://api.github.com/repos/o/r/check-runs"
    assert captured["body"]["conclusion"] == "failure"  # violating ⇒ blocked
    assert captured["body"]["name"] == "FedRAMP 20x KSI Gate"


def test_check_run_handles_http_error(monkeypatch) -> None:
    import urllib.error

    def boom(req, timeout=30):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(gh.urllib.request, "urlopen", boom)
    assert (
        post_check_run(
            _report(), decide(_report(), "enforce"), token="t", repository="o/r", head_sha="a" * 40
        )
        is None
    )


def test_pr_comment_creates_when_absent(monkeypatch) -> None:
    calls = []

    def fake_urlopen(req, timeout=30):
        calls.append((req.method, req.full_url))
        if req.method == "GET":
            return _FakeResp([])  # no existing comments
        return _FakeResp({"id": 77})

    monkeypatch.setattr(gh.urllib.request, "urlopen", fake_urlopen)
    cid = upsert_pr_comment(_report(), token="t", repository="o/r", pr_number=5)
    assert cid == 77
    assert ("POST", "https://api.github.com/repos/o/r/issues/5/comments") in calls


def test_pr_comment_updates_when_present(monkeypatch) -> None:
    from fedramp_ksi.reporters.summary import PR_COMMENT_MARKER

    methods = []

    def fake_urlopen(req, timeout=30):
        methods.append(req.method)
        if req.method == "GET":
            return _FakeResp([{"id": 9, "body": f"{PR_COMMENT_MARKER} old"}])
        return _FakeResp({"id": 9})

    monkeypatch.setattr(gh.urllib.request, "urlopen", fake_urlopen)
    cid = upsert_pr_comment(_report(), token="t", repository="o/r", pr_number=5)
    assert cid == 9
    assert "PATCH" in methods


def test_pr_number_from_env(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_REF", "refs/pull/123/merge")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert gh._pr_number_from_env() == 123


def test_pr_number_from_event_file(monkeypatch, tmp_path) -> None:
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {"number": 88}}))
    monkeypatch.delenv("GITHUB_REF", raising=False)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    assert gh._pr_number_from_env() == 88
