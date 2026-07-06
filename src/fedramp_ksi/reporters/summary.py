"""Markdown summary — used for the PR comment and $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

from ..model import Status
from .report import RunReport

_EMOJI = {
    Status.PASS: "✅",
    Status.FAIL: "❌",
    Status.PARTIAL: "🟡",
    Status.NA: "⚪",
    Status.MANUAL: "📝",
    Status.ERROR: "⚠️",
}

# Marker so the PR-comment updater can find and replace its own comment.
PR_COMMENT_MARKER = "<!-- fedramp-20x-ksi-action -->"


def build_summary(report: RunReport, *, pr_comment: bool = False) -> str:
    gate = report.gate_status
    header_emoji = _EMOJI.get(gate, "❓")
    counts = report.findings_by_severity()

    lines: list[str] = []
    if pr_comment:
        lines.append(PR_COMMENT_MARKER)
    lines += [
        f"## {header_emoji} FedRAMP 20x KSI Gate — `{gate.value}`",
        "",
        f"**Class {report.target_class.value}** · ruleset `{report.ruleset_version}` · "
        f"enforced failures: **{report.enforced_failures}**",
        "",
        f"Findings: 🔴 {counts['critical']} critical · 🟠 {counts['high']} high · "
        f"🟡 {counts['medium']} medium · ⚪ {counts['low']} low",
        "",
        "| KSI | Disposition | Status |",
        "|---|---|---|",
    ]
    for r in _sorted_results(report):
        e = _EMOJI.get(r.status, "❓")
        enforce_tag = "enforce" if r.enforced else r.disposition
        lines.append(f"| `{r.ksi_id}` {r.name} | {enforce_tag} | {e} {r.status.value} |")

    fails = [f for f in report.live_findings if f.status == Status.FAIL]
    if fails:
        lines += ["", "### ❌ Failing checks", ""]
        for f in fails:
            loc = f" — `{f.resource_address}`" if f.resource_address else ""
            lines.append(f"- **{f.ksi_id}**{loc}: {f.message}")
            if f.remediation:
                lines.append(f"  - _Fix:_ {f.remediation}")

    waived = report.suppressed_findings
    if waived:
        lines += ["", f"<sub>{len(waived)} finding(s) suppressed by waiver/baseline.</sub>"]

    lines.append("")
    return "\n".join(lines)


def _sorted_results(report: RunReport):
    # Failures first, then by KSI id — stable and readable.
    order = {
        Status.FAIL: 0,
        Status.ERROR: 1,
        Status.PARTIAL: 2,
        Status.PASS: 3,
        Status.MANUAL: 4,
        Status.NA: 5,
    }
    return sorted(report.results, key=lambda r: (order.get(r.status, 9), r.ksi_id))
