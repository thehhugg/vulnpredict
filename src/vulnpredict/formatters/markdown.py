"""Markdown summary formatter for PR comments.

Produces a concise Markdown report suitable for posting as a GitHub, GitLab,
or Bitbucket PR comment. The output is designed to fit within typical PR
comment size limits (~65 KB for GitHub).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_EMOJI = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",      # orange circle
    "medium": "\U0001f7e1",    # yellow circle
    "low": "\U0001f7e2",       # green circle
    "info": "\U0001f535",      # blue circle
}


def _classify_severity(finding: Dict[str, Any]) -> str:
    """Classify a finding into a severity level."""
    # Use explicit severity if present
    sev = finding.get("severity", "").lower()
    if sev in _SEVERITY_ORDER:
        return sev

    # Fall back to vuln_score
    score = finding.get("vuln_score")
    if score is not None:
        if score >= 0.8:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    return "medium"


def _finding_message(finding: Dict[str, Any]) -> str:
    """Extract a human-readable message from a finding."""
    if "rule_description" in finding:
        return str(finding["rule_description"])
    if "message" in finding:
        return str(finding["message"])

    ftype = finding.get("type", "")
    if ftype == "dangerous_function":
        return f"Dangerous function call: {finding.get('function', '?')}"
    if ftype in ("taint_analysis", "interprocedural_taint"):
        sink = finding.get("sink", "?")
        var = finding.get("variable", finding.get("tainted_var", "?"))
        return f"Tainted variable `{var}` flows to sink `{sink}`"
    if ftype == "hardcoded_secret":
        return f"Hardcoded secret: {finding.get('variable', '?')}"
    if ftype == "high_complexity":
        return f"High cyclomatic complexity: {finding.get('complexity', '?')}"

    return str(finding.get("name", "Unknown finding"))


def _finding_location(finding: Dict[str, Any]) -> str:
    """Extract file:line location from a finding."""
    f = finding.get("file", finding.get("filename", ""))
    line = finding.get("line", finding.get("sink_line", ""))
    if f and line:
        return f"`{f}:{line}`"
    if f:
        return f"`{f}`"
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Maximum number of individual findings to show in the details section.
# This keeps the output within PR comment size limits.
MAX_FINDINGS_DETAIL = 50


def format_markdown(
    findings: List[Dict[str, Any]],
    scan_path: str,
    scan_duration: Optional[float] = None,
    file_count: Optional[int] = None,
    suppressed_count: int = 0,
) -> str:
    """Format scan findings as a Markdown summary for PR comments.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.
        scan_duration: Scan duration in seconds (optional).
        file_count: Number of files scanned (optional).
        suppressed_count: Number of suppressed findings.

    Returns:
        Markdown string with the scan summary.
    """
    lines: List[str] = []

    # --- Header ---
    total = len(findings)
    if total == 0:
        lines.append("## \u2705 VulnPredict Scan \u2014 No Findings")
    else:
        lines.append(f"## \u26a0\ufe0f VulnPredict Scan \u2014 {total} Finding{'s' if total != 1 else ''}")
    lines.append("")

    # --- Severity summary table ---
    severity_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }
    for f in findings:
        sev = _classify_severity(f)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts[sev]
        emoji = _SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev.capitalize()} | {count} |")
    lines.append("")

    # --- Metadata ---
    meta_parts: List[str] = [f"**Path**: `{scan_path}`"]
    if file_count is not None:
        meta_parts.append(f"**Files scanned**: {file_count}")
    if scan_duration is not None:
        meta_parts.append(f"**Duration**: {scan_duration:.2f}s")
    if suppressed_count > 0:
        meta_parts.append(f"**Suppressed**: {suppressed_count}")
    lines.append(" | ".join(meta_parts))
    lines.append("")

    if total == 0:
        lines.append("No vulnerabilities detected. Great job!")
        lines.append("")
        return "\n".join(lines)

    # --- Top findings table ---
    # Sort by severity (critical first), then by score
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(_classify_severity(f), 99),
            -(f.get("vuln_score", 0) or 0),
        ),
    )

    lines.append("### Top Findings")
    lines.append("")
    lines.append("| # | Severity | Location | Description |")
    lines.append("|---|---|---|---|")

    shown = min(len(sorted_findings), 20)
    for i, finding in enumerate(sorted_findings[:shown], 1):
        sev = _classify_severity(finding)
        emoji = _SEVERITY_EMOJI.get(sev, "")
        loc = _finding_location(finding)
        msg = _finding_message(finding)
        # Escape pipe characters in messages for table cells
        msg = msg.replace("|", "\\|")
        lines.append(f"| {i} | {emoji} {sev.capitalize()} | {loc} | {msg} |")

    if len(sorted_findings) > shown:
        lines.append(f"| | | | *... and {len(sorted_findings) - shown} more findings* |")
    lines.append("")

    # --- Collapsible details for each finding ---
    detail_count = min(len(sorted_findings), MAX_FINDINGS_DETAIL)
    if detail_count > 0:
        lines.append("### Finding Details")
        lines.append("")

        for i, finding in enumerate(sorted_findings[:detail_count], 1):
            sev = _classify_severity(finding)
            emoji = _SEVERITY_EMOJI.get(sev, "")
            msg = _finding_message(finding)
            loc = _finding_location(finding)

            lines.append(f"<details>")
            lines.append(f"<summary>{emoji} <strong>#{i}</strong> {msg}</summary>")
            lines.append("")

            # Detail table
            lines.append("| Field | Value |")
            lines.append("|---|---|")
            lines.append(f"| **Severity** | {sev.capitalize()} |")
            if loc:
                lines.append(f"| **Location** | {loc} |")

            ftype = finding.get("type", "")
            if ftype:
                lines.append(f"| **Type** | {ftype} |")

            rule_id = finding.get("rule_id", "")
            if rule_id:
                lines.append(f"| **Rule** | `{rule_id}` |")

            cwe = finding.get("cwe", "")
            if cwe:
                lines.append(f"| **CWE** | [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html) |")

            score = finding.get("vuln_score")
            if score is not None:
                lines.append(f"| **Score** | {score:.2f} |")

            confidence = finding.get("confidence", "")
            if confidence and not isinstance(confidence, float):
                lines.append(f"| **Confidence** | {confidence} |")

            # Trace / call chain
            trace = finding.get("trace", finding.get("call_chain"))
            if trace:
                lines.append("")
                lines.append("**Trace**:")
                lines.append("```")
                if isinstance(trace, list):
                    for step in trace:
                        lines.append(f"  {step}")
                else:
                    lines.append(f"  {trace}")
                lines.append("```")

            lines.append("")
            lines.append("</details>")
            lines.append("")

        if len(sorted_findings) > detail_count:
            lines.append(
                f"*{len(sorted_findings) - detail_count} additional findings omitted. "
                f"Run with `--format json` for the complete report.*"
            )
            lines.append("")

    # --- Footer ---
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("---")
    lines.append(f"*Generated by [VulnPredict](https://github.com/thehhugg/vulnpredict) at {ts}*")
    lines.append("")

    return "\n".join(lines)


def write_markdown(
    findings: List[Dict[str, Any]],
    scan_path: str,
    output_path: str,
    scan_duration: Optional[float] = None,
    file_count: Optional[int] = None,
    suppressed_count: int = 0,
) -> None:
    """Format and write scan findings to a Markdown file.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.
        output_path: Path to write the Markdown output file.
        scan_duration: Scan duration in seconds (optional).
        file_count: Number of files scanned (optional).
        suppressed_count: Number of suppressed findings.
    """
    md_str = format_markdown(
        findings,
        scan_path,
        scan_duration=scan_duration,
        file_count=file_count,
        suppressed_count=suppressed_count,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_str)
