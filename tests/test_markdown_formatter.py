"""Unit tests for the Markdown summary formatter (vulnpredict.formatters.markdown)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

import pytest

from vulnpredict.formatters.markdown import (
    MAX_FINDINGS_DETAIL,
    _classify_severity,
    _finding_location,
    _finding_message,
    format_markdown,
    write_markdown,
)

# ---------------------------------------------------------------------------
# Sample findings
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS: List[Dict[str, Any]] = [
    {
        "type": "taint_analysis",
        "severity": "high",
        "file": "app/views.py",
        "line": 42,
        "source": ["request.args.get('q')"],
        "sink": "cursor.execute",
        "variable": "query",
        "vuln_score": 0.92,
        "rule_id": "VP-PY-001",
        "cwe": "CWE-89",
        "trace": ["request.args.get('q')", "query = ...", "cursor.execute(query)"],
    },
    {
        "type": "dangerous_function",
        "severity": "critical",
        "file": "utils/eval_helper.py",
        "line": 15,
        "function": "eval",
        "vuln_score": 0.95,
        "rule_id": "VP-PY-002",
        "cwe": "CWE-95",
    },
    {
        "type": "hardcoded_secret",
        "severity": "medium",
        "file": "config/settings.py",
        "line": 88,
        "variable": "API_KEY",
        "vuln_score": 0.55,
    },
    {
        "type": "high_complexity",
        "severity": "low",
        "file": "core/parser.py",
        "line": 200,
        "complexity": 25,
        "vuln_score": 0.2,
    },
]


# ---------------------------------------------------------------------------
# format_markdown tests
# ---------------------------------------------------------------------------


class TestFormatMarkdown:
    """Tests for the format_markdown function."""

    def test_returns_string(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/project")
        assert isinstance(result, str)

    def test_header_with_findings(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/project")
        assert "VulnPredict Scan" in result
        assert "4 Findings" in result

    def test_header_no_findings(self) -> None:
        result = format_markdown([], scan_path="/project")
        assert "No Findings" in result

    def test_severity_summary_table(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/project")
        assert "| Severity | Count |" in result
        assert "Critical" in result
        assert "High" in result
        assert "Medium" in result
        assert "Low" in result

    def test_severity_counts_correct(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/project")
        # 1 critical, 1 high, 1 medium, 1 low
        lines = result.split("\n")
        # Find the severity summary table (between header separator and blank line)
        in_summary = False
        summary_rows: list[str] = []
        for line in lines:
            if line == "|---|---|":
                in_summary = True
                continue
            if in_summary:
                if line.startswith("|") and "Critical" in line or "High" in line or "Medium" in line or "Low" in line:
                    summary_rows.append(line)
                elif not line.startswith("|"):
                    break
        # Should have exactly 4 severity rows
        assert len(summary_rows) == 4
        # Each should have count 1
        for row in summary_rows:
            assert "| 1 |" in row

    def test_scan_path_shown(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/my/project")
        assert "`/my/project`" in result

    def test_file_count_shown(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p", file_count=42)
        assert "42" in result

    def test_duration_shown(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p", scan_duration=1.234)
        assert "1.23" in result

    def test_suppressed_count_shown(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p", suppressed_count=5)
        assert "5" in result

    def test_top_findings_table(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        assert "### Top Findings" in result
        assert "| # | Severity | Location | Description |" in result

    def test_findings_sorted_by_severity(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        lines = result.split("\n")
        # Find the top findings table rows (after header)
        table_start = None
        for i, line in enumerate(lines):
            if "| # | Severity" in line:
                table_start = i + 2  # skip header and separator
                break
        assert table_start is not None
        # First row should be critical
        assert "Critical" in lines[table_start]

    def test_collapsible_details(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        assert "<details>" in result
        assert "<summary>" in result
        assert "</details>" in result

    def test_finding_details_include_fields(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        assert "VP-PY-001" in result or "VP-PY-002" in result
        assert "CWE-89" in result or "CWE-95" in result

    def test_trace_shown(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        assert "Trace" in result
        assert "cursor.execute(query)" in result

    def test_footer_present(self) -> None:
        result = format_markdown(SAMPLE_FINDINGS, scan_path="/p")
        assert "Generated by" in result
        assert "VulnPredict" in result

    def test_empty_findings_message(self) -> None:
        result = format_markdown([], scan_path="/p")
        assert "No vulnerabilities detected" in result

    def test_pipe_characters_escaped(self) -> None:
        findings = [
            {
                "type": "test",
                "severity": "low",
                "message": "foo | bar | baz",
                "file": "test.py",
                "line": 1,
            }
        ]
        result = format_markdown(findings, scan_path="/p")
        # Pipes in table cells should be escaped
        assert "foo \\| bar \\| baz" in result

    def test_single_finding_no_plural(self) -> None:
        findings = [SAMPLE_FINDINGS[0]]
        result = format_markdown(findings, scan_path="/p")
        assert "1 Finding" in result
        assert "1 Findings" not in result


# ---------------------------------------------------------------------------
# Truncation tests
# ---------------------------------------------------------------------------


class TestFormatMarkdownTruncation:
    """Tests for output truncation to fit PR comment limits."""

    def test_more_than_20_findings_shows_ellipsis(self) -> None:
        findings = [
            {
                "type": "dangerous_function",
                "severity": "medium",
                "file": f"file_{i}.py",
                "line": i,
                "function": "eval",
            }
            for i in range(25)
        ]
        result = format_markdown(findings, scan_path="/p")
        assert "more findings" in result

    def test_more_than_max_detail_shows_omitted(self) -> None:
        findings = [
            {
                "type": "dangerous_function",
                "severity": "medium",
                "file": f"file_{i}.py",
                "line": i,
                "function": "eval",
            }
            for i in range(MAX_FINDINGS_DETAIL + 10)
        ]
        result = format_markdown(findings, scan_path="/p")
        assert "additional findings omitted" in result


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestClassifySeverity:
    """Tests for _classify_severity."""

    def test_explicit_severity(self) -> None:
        assert _classify_severity({"severity": "critical"}) == "critical"
        assert _classify_severity({"severity": "HIGH"}) == "high"

    def test_vuln_score_fallback(self) -> None:
        assert _classify_severity({"vuln_score": 0.9}) == "high"
        assert _classify_severity({"vuln_score": 0.6}) == "medium"
        assert _classify_severity({"vuln_score": 0.3}) == "low"

    def test_default_medium(self) -> None:
        assert _classify_severity({}) == "medium"


class TestFindingMessage:
    """Tests for _finding_message."""

    def test_rule_description(self) -> None:
        assert _finding_message({"rule_description": "Test"}) == "Test"

    def test_message_field(self) -> None:
        assert _finding_message({"message": "Hello"}) == "Hello"

    def test_dangerous_function(self) -> None:
        msg = _finding_message({"type": "dangerous_function", "function": "eval"})
        assert "eval" in msg

    def test_taint_analysis(self) -> None:
        msg = _finding_message({"type": "taint_analysis", "sink": "execute", "variable": "q"})
        assert "execute" in msg
        assert "q" in msg

    def test_hardcoded_secret(self) -> None:
        msg = _finding_message({"type": "hardcoded_secret", "variable": "KEY"})
        assert "KEY" in msg

    def test_fallback(self) -> None:
        msg = _finding_message({"name": "test-finding"})
        assert "test-finding" in msg


class TestFindingLocation:
    """Tests for _finding_location."""

    def test_file_and_line(self) -> None:
        loc = _finding_location({"file": "app.py", "line": 10})
        assert loc == "`app.py:10`"

    def test_file_only(self) -> None:
        loc = _finding_location({"file": "app.py"})
        assert loc == "`app.py`"

    def test_empty(self) -> None:
        loc = _finding_location({})
        assert loc == ""

    def test_filename_key(self) -> None:
        loc = _finding_location({"filename": "test.py", "sink_line": 5})
        assert loc == "`test.py:5`"


# ---------------------------------------------------------------------------
# write_markdown tests
# ---------------------------------------------------------------------------


class TestWriteMarkdown:
    """Tests for write_markdown."""

    def test_writes_file(self, tmp_path: Any) -> None:
        path = os.path.join(str(tmp_path), "report.md")
        write_markdown(SAMPLE_FINDINGS, scan_path="/p", output_path=path)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "VulnPredict Scan" in content

    def test_empty_findings_writes_file(self, tmp_path: Any) -> None:
        path = os.path.join(str(tmp_path), "report.md")
        write_markdown([], scan_path="/p", output_path=path)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "No Findings" in content
