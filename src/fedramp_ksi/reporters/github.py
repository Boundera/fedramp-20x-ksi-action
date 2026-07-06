"""GitHub Check Run + PR comment reporters (SPEC §2, §13).

Stdlib-only (urllib) so the action carries no HTTP dependency and talks to
exactly one host: the GitHub API (``api.github.com`` by default, or
``$GITHUB_API_URL`` for GHES). Both reporters degrade gracefully — they log and
return ``None`` when no token/context is available rather than raising, so a
missing permission never crashes the gate.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

from ..model import Status
from .report import RunReport
from .summary import PR_COMMENT_MARKER, build_summary

if TYPE_CHECKING:
    from ..gate import GateDecision

logger = logging.getLogger(__name__)

API_VERSION = "2022-11-28"
USER_AGENT = "Boundera-fedramp-20x-ksi-action"

_CONCLUSION = {
    Status.PASS: "success",
    Status.FAIL: "failure",
    Status.ERROR: "neutral",
    Status.NA: "neutral",
    Status.PARTIAL: "neutral",
    Status.MANUAL: "neutral",
}


def _api_base() -> str:
    return os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")


def _request(
    method: str, url: str, token: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url=url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — fixed api host
        body: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return body


def post_check_run(
    report: RunReport,
    decision: GateDecision,  # noqa: F821 — TYPE_CHECKING import
    *,
    token: str | None = None,
    repository: str | None = None,
    head_sha: str | None = None,
) -> int | None:
    """Post a single aggregate 'FedRAMP 20x KSI Gate' Check Run on the commit."""
    token = token or os.environ.get("GITHUB_TOKEN")
    repository = repository or os.environ.get("GITHUB_REPOSITORY")
    head_sha = head_sha or report.meta.commit_sha or os.environ.get("GITHUB_SHA")
    if not (token and repository and head_sha):
        logger.warning("Skipping Check Run: missing token/repository/head_sha.")
        return None

    conclusion = "failure" if decision.blocked else _CONCLUSION.get(report.gate_status, "neutral")
    payload = {
        "name": "FedRAMP 20x KSI Gate",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": f"KSI Gate: {report.gate_status.value} — {decision.reason}",
            "summary": build_summary(report),
        },
    }
    try:
        body = _request("POST", f"{_api_base()}/repos/{repository}/check-runs", token, payload)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("Failed to post Check Run: %s", exc)
        return None
    check_id = body.get("id")
    return check_id if isinstance(check_id, int) else None


def upsert_pr_comment(
    report: RunReport,
    *,
    token: str | None = None,
    repository: str | None = None,
    pr_number: int | None = None,
) -> int | None:
    """Post or refresh the single PR summary comment (idempotent via marker)."""
    token = token or os.environ.get("GITHUB_TOKEN")
    repository = repository or os.environ.get("GITHUB_REPOSITORY")
    pr_number = pr_number if pr_number is not None else _pr_number_from_env()
    if not (token and repository and pr_number):
        logger.warning("Skipping PR comment: missing token/repository/pr_number.")
        return None

    body_md = build_summary(report, pr_comment=True)
    base = f"{_api_base()}/repos/{repository}/issues/{pr_number}/comments"
    try:
        existing = _request("GET", base, token)
        comment_id = None
        if isinstance(existing, list):
            for c in existing:
                if PR_COMMENT_MARKER in (c.get("body") or ""):
                    comment_id = c.get("id")
                    break
        if comment_id:
            url = f"{_api_base()}/repos/{repository}/issues/comments/{comment_id}"
            body = _request("PATCH", url, token, {"body": body_md})
        else:
            body = _request("POST", base, token, {"body": body_md})
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("Failed to upsert PR comment: %s", exc)
        return None
    cid = body.get("id")
    return cid if isinstance(cid, int) else None


def _pr_number_from_env() -> int | None:
    ref = os.environ.get("GITHUB_REF", "")  # refs/pull/<n>/merge
    if ref.startswith("refs/pull/"):
        try:
            return int(ref.split("/")[2])
        except (IndexError, ValueError):
            pass
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.isfile(event_path):
        try:
            with open(event_path, encoding="utf-8") as fh:
                event = json.loads(fh.read())
            num = event.get("pull_request", {}).get("number") or event.get("number")
            return int(num) if num else None
        except (ValueError, OSError):
            pass
    return None
