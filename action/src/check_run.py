"""GitHub Check Run posting — the architectural centerpiece of this action.

This module is the single piece of code that replaces the entire `app/` directory
in chukyjack/fedrampgpt-ksi-checker. Instead of relying on a vendor-hosted
GitHub App backend to receive webhooks and post Check Runs, this module posts
them directly from inside the customer's GitHub Actions runner using the
workflow's built-in GITHUB_TOKEN.

Design constraints:
- Uses only the Python stdlib (urllib.request). No httpx, no requests, no
  third-party HTTP libraries. Keeps the action's runtime dependencies minimal
  and audit-friendly.
- Talks to exactly one host: api.github.com.
- Reads GITHUB_TOKEN from the environment. The workflow must declare
  `permissions: { checks: write }` for the token to have the right scope.
- Returns the Check Run ID on success, raises on failure. The caller decides
  whether to fail the workflow or continue.

Permissions reference:
- https://docs.github.com/en/rest/checks/runs#create-a-check-run
- https://docs.github.com/en/actions/security-guides/automatic-token-authentication
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "Boundera-fedramp-20x-ksi-action"

# Map KSI evaluation status → GitHub Check Run conclusion.
# ERROR is mapped to "neutral" rather than "failure" so transient tooling
# errors don't block a PR; PASS/FAIL behave as expected.
_STATUS_TO_CONCLUSION: dict[str, str] = {
    "PASS": "success",
    "FAIL": "failure",
    "ERROR": "neutral",
}


class CheckRunError(Exception):
    """Raised when posting a Check Run fails."""


def status_to_conclusion(status: str) -> str:
    """Map a KSI evaluation status to a GitHub Check Run conclusion.

    Args:
        status: One of PASS, FAIL, ERROR. Case-insensitive.

    Returns:
        GitHub conclusion: success, failure, or neutral.
    """
    return _STATUS_TO_CONCLUSION.get(status.upper(), "neutral")


def post_check_run(
    *,
    ksi_id: str,
    ksi_name: str,
    status: str,
    summary_markdown: str,
    head_sha: str | None = None,
    repository: str | None = None,
    title: str | None = None,
    token: str | None = None,
    timeout_seconds: int = 30,
) -> int:
    """Create a Check Run on the commit currently being evaluated.

    Args:
        ksi_id: The canonical mnemonic ID (e.g., 'KSI-MLA-EVC').
        ksi_name: Human-readable name (e.g., 'Evaluating Configurations').
        status: Evaluation status (PASS, FAIL, ERROR).
        summary_markdown: Markdown body for the Check Run summary panel.
        head_sha: Commit SHA. Defaults to env var GITHUB_SHA.
        repository: 'owner/repo'. Defaults to env var GITHUB_REPOSITORY.
        title: Check Run title. Defaults to a derived title from ksi_id.
        token: GitHub token. Defaults to env var GITHUB_TOKEN.
        timeout_seconds: HTTP request timeout.

    Returns:
        The created Check Run ID.

    Raises:
        CheckRunError: If required inputs are missing or the API call fails.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    repository = repository or os.environ.get("GITHUB_REPOSITORY")
    head_sha = head_sha or os.environ.get("GITHUB_SHA")

    if not token:
        raise CheckRunError(
            "GITHUB_TOKEN is not set. Ensure the workflow has 'permissions: { checks: write }'."
        )
    if not repository:
        raise CheckRunError(
            "GITHUB_REPOSITORY is not set. This module is meant to run inside GitHub Actions."
        )
    if not head_sha:
        raise CheckRunError(
            "GITHUB_SHA is not set. This module is meant to run inside GitHub Actions."
        )

    check_name = f"{ksi_id} — {ksi_name}"
    payload: dict[str, Any] = {
        "name": check_name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": status_to_conclusion(status),
        "output": {
            "title": title or f"FedRAMP 20x KSI Evidence: {ksi_id}",
            "summary": summary_markdown,
        },
    }

    url = f"{GITHUB_API_BASE}/repos/{repository}/check-runs"
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    )

    logger.info(
        "Posting Check Run: ksi_id=%s repo=%s sha=%s conclusion=%s",
        ksi_id,
        repository,
        head_sha[:7] if head_sha else "?",
        payload["conclusion"],
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = ""
        with contextlib.suppress(Exception):
            error_body = exc.read().decode("utf-8")
        raise CheckRunError(
            f"Failed to post Check Run for {ksi_id}: HTTP {exc.code} {exc.reason}. "
            f"Response: {error_body[:500]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CheckRunError(f"Failed to reach GitHub API for {ksi_id}: {exc.reason}") from exc

    check_run_id = body.get("id")
    if not isinstance(check_run_id, int):
        raise CheckRunError(
            f"Unexpected response from GitHub Checks API: missing 'id'. Body: {body}"
        )

    logger.info(
        "Check Run created: id=%s name=%r conclusion=%s",
        check_run_id,
        check_name,
        payload["conclusion"],
    )
    return check_run_id


def build_summary_markdown(
    *,
    ksi_id: str,
    ksi_name: str,
    ksi_statement: str,
    status: str,
    criteria: list[dict[str, Any]] | dict[str, Any],
    repository: str,
    commit_sha: str,
    trigger_event: str,
    artifact_name: str | None = None,
    run_url: str | None = None,
    extra_summary_lines: list[str] | None = None,
) -> str:
    """Build the markdown body for a Check Run summary panel.

    Mirrors the format used by the original chukyjack/fedrampgpt-ksi-checker app
    so that customers migrating from that action see no surface change in the
    Check Run UI.

    Args:
        ksi_id: Canonical mnemonic ID.
        ksi_name: Human-readable name.
        ksi_statement: Verbatim FRMR statement text.
        status: Evaluation status (PASS, FAIL, ERROR).
        criteria: Per-criterion evaluation results. Accepts either a list of
            criterion dicts (MLA-style) or a dict keyed by criterion ID
            (CNA-style).
        repository: 'owner/repo'.
        commit_sha: Commit SHA.
        trigger_event: GitHub event that triggered the workflow.
        artifact_name: Name of the uploaded evidence artifact, if any.
        run_url: URL to the workflow run, if available.
        extra_summary_lines: Optional extra '- ' bullets to insert under
            Summary (e.g., security-group counts for CNA-RNT).

    Returns:
        Markdown string ready to send in the Check Run `output.summary` field.
    """
    status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(status.upper(), "❓")

    lines: list[str] = [
        f"## {status_emoji} {ksi_id}: {ksi_name}",
        "",
        "### Requirement",
        f"> {ksi_statement}",
        "",
        f"### Status: **{status.upper()}**",
        "",
    ]

    if extra_summary_lines:
        lines.append("### Summary")
        for line in extra_summary_lines:
            lines.append(line if line.startswith(("-", "*")) else f"- {line}")
        lines.append("")

    lines.append("### Criteria Evaluation")
    lines.append("")
    lines.append("| Criterion | Name | Status | Details |")
    lines.append("|---|---|---|---|")

    iter_criteria: list[tuple[str, dict[str, Any]]]
    if isinstance(criteria, dict):
        iter_criteria = list(criteria.items())
    else:
        iter_criteria = [(c.get("id", "?"), c) for c in criteria]

    for crit_id, crit in iter_criteria:
        crit_status = (crit.get("status") or "UNKNOWN").upper()
        crit_emoji = {
            "PASS": "✅",
            "FAIL": "❌",
            "ERROR": "⚠️",
            "SKIP": "⏭️",
        }.get(crit_status, "❓")
        findings = crit.get("findings")
        details = f"{len(findings)} finding(s)" if findings else crit.get("reason", "N/A")
        lines.append(
            f"| {crit.get('id', crit_id)} | {crit.get('name', 'N/A')} | "
            f"{crit_emoji} {crit_status} | {details} |"
        )
    lines.append("")

    lines.append("### Scope")
    lines.append(f"- **Repository:** {repository}")
    lines.append(f"- **Commit:** `{commit_sha[:7] if len(commit_sha) > 7 else commit_sha}`")
    lines.append(f"- **Trigger:** `{trigger_event}`")
    if run_url:
        lines.append(f"- **Run:** {run_url}")
    lines.append("")

    if artifact_name:
        lines.append("### Evidence Artifact")
        lines.append(f"- **Name:** `{artifact_name}`")
        lines.append("")

    lines.append("---")
    lines.append(
        "*Generated by [Boundera/fedramp-20x-ksi-action]"
        "(https://github.com/Boundera/fedramp-20x-ksi-action). "
        "No vendor server in the loop.*"
    )

    return "\n".join(lines)
