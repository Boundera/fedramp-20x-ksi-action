"""SPEC §13/§15.9 — default mode makes no network calls; the only outbound
host in the package is the GitHub API.

Guards against a regression that introduces a new HTTP client or a call to a
non-GitHub host from the delivered engine.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "fedramp_ksi"

# Modules permitted to make outbound HTTP calls, and the only one that should.
_NETWORK_MODULE = SRC / "reporters" / "github.py"

_HTTP_CLIENT_PATTERNS = [
    r"\brequests\.",
    r"\bhttpx\.",
    r"\baiohttp\b",
    r"urllib\.request\.urlopen",
    r"http\.client",
    r"socket\.socket",
]


def _py_files() -> list[Path]:
    return list(SRC.rglob("*.py"))


def test_only_github_reporter_makes_network_calls() -> None:
    offenders: list[str] = []
    for path in _py_files():
        if path == _NETWORK_MODULE:
            continue
        text = path.read_text(encoding="utf-8")
        for pat in _HTTP_CLIENT_PATTERNS:
            if re.search(pat, text):
                offenders.append(f"{path.name}: {pat}")
    assert not offenders, f"unexpected network usage outside github.py: {offenders}"


def test_no_third_party_http_clients_anywhere() -> None:
    # The whole package must be stdlib-only for HTTP (no requests/httpx).
    for path in _py_files():
        text = path.read_text(encoding="utf-8")
        assert "import requests" not in text, f"{path} imports requests"
        assert "import httpx" not in text, f"{path} imports httpx"


def test_github_reporter_only_targets_github_api_host() -> None:
    text = _NETWORK_MODULE.read_text(encoding="utf-8")
    # Base URL is api.github.com or the GHES GITHUB_API_URL — no other hosts.
    urls = re.findall(r"https?://[^\s\"')]+", text)
    for url in urls:
        assert "api.github.com" in url or "github.com/Boundera" in url, f"unexpected host: {url}"
    assert 'os.environ.get("GITHUB_API_URL"' in text or "GITHUB_API_URL" in text
