"""Tests for the HTML report formatter."""

import os
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "file": "app/server.py",
        "line": 42,
        "function": "handle_request",
        "type": "sql_injection",
        "detail": "User input passed directly to cursor.execute()",
        "severity": "critical",
        "score": 0.95,
    },
    {
        "file": "app/server.py",
        "line": 88,
        "function": "process_data",
        "type": "eval_usage",
        "detail": "eval() called with user-controlled input",
        "severity": "high",
        "score": 0.82,
    },
    {
        "file": "utils/helpers.py",
        "line": 15,
        "function": "load_config",
        "type": "hardcoded_secret",
        "detail": "Hardcoded API key detected",
        "severity": "medium",
        "score": 0.55,
    },
    {
        "file": "utils/helpers.py",
        "line": 30,
        "function": "compute",
        "type": "high_complexity",
        "detail": "Cyclomatic complexity of 25",
        "severity": "low",
        "score": 0.3,
    },
]


# ---------------------------------------------------------------------------
# Tests for format_html
# ---------------------------------------------------------------------------


class TestFormatHtml:
    """Tests for the format_html function."""

    def test_returns_valid_html_document(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert result.startswith("<!DOCTYPE html>")
        assert "</html>" in result

    def test_contains_title(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "<title>VulnPredict Scan Report</title>" in result

    def test_contains_scan_path(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/my/project")
        assert "/my/project" in result

    def test_contains_severity_counts(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        # Total findings count
        assert ">4<" in result  # total findings

    def test_contains_findings_table(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "findingsTable" in result
        assert "sql_injection" in result
        assert "eval_usage" in result
        assert "hardcoded_secret" in result

    def test_contains_file_paths(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "app/server.py" in result
        assert "utils/helpers.py" in result

    def test_contains_remediation_guidance(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "parameterized queries" in result  # SQL injection remediation
        assert "ast.literal_eval" in result  # eval remediation

    def test_contains_charts(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "sevChart" in result
        assert "fileChart" in result
        assert "typeChart" in result

    def test_contains_inline_css(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "<style>" in result
        assert "</style>" in result

    def test_contains_inline_javascript(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "<script>" in result
        assert "drawDoughnut" in result
        assert "filterTable" in result

    def test_no_external_dependencies(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        # Should not reference external CSS or JS
        assert 'rel="stylesheet"' not in result
        assert '<script src=' not in result
        assert '<link href=' not in result

    def test_empty_findings(self):
        from vulnpredict.formatters.html import format_html

        result = format_html([], scan_path="/app")
        assert "<!DOCTYPE html>" in result
        assert ">0<" in result  # total findings = 0

    def test_html_escaping(self):
        from vulnpredict.formatters.html import format_html

        xss_findings = [
            {
                "file": "<script>alert('xss')</script>",
                "line": 1,
                "function": "test",
                "type": "test",
                "detail": '<img onerror="alert(1)">',
                "severity": "high",
            }
        ]
        result = format_html(xss_findings, scan_path="/app")
        assert "<script>alert(" not in result.split("<script>")[0]  # Not in HTML body
        assert "&lt;script&gt;" in result  # Properly escaped

    def test_scan_duration_displayed(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app", scan_duration=3.14)
        assert "3.14s" in result

    def test_file_count_displayed(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app", file_count=42)
        assert ">42<" in result

    def test_severity_badge_colors(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        assert "#dc2626" in result  # critical color
        assert "#ea580c" in result  # high color
        assert "#d97706" in result  # medium color
        assert "#2563eb" in result  # low color

    def test_findings_sorted_by_severity(self):
        from vulnpredict.formatters.html import format_html

        result = format_html(SAMPLE_FINDINGS, scan_path="/app")
        # Critical should appear before Low in the table
        crit_pos = result.find("CRITICAL")
        low_pos = result.find("LOW")
        assert crit_pos < low_pos


class TestWriteHtml:
    """Tests for the write_html function."""

    def test_writes_file(self):
        from vulnpredict.formatters.html import write_html

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            write_html(SAMPLE_FINDINGS, scan_path="/app", output_path=path)
            assert os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "sql_injection" in content
        finally:
            os.unlink(path)

    def test_writes_empty_findings(self):
        from vulnpredict.formatters.html import write_html

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            write_html([], scan_path="/app", output_path=path)
            assert os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
        finally:
            os.unlink(path)

    def test_file_is_utf8(self):
        from vulnpredict.formatters.html import write_html

        unicode_findings = [
            {
                "file": "app/unicode_test.py",
                "line": 1,
                "function": "test",
                "type": "test",
                "detail": "Unicode: \u00e9\u00e0\u00fc\u00f1 \u2014 em dash",
                "severity": "low",
            }
        ]
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            write_html(unicode_findings, scan_path="/app", output_path=path)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "\u00e9\u00e0\u00fc\u00f1" in content
        finally:
            os.unlink(path)


class TestSeverityClassification:
    """Tests for _classify_severity helper."""

    def test_explicit_severity(self):
        from vulnpredict.formatters.html import _classify_severity

        assert _classify_severity({"severity": "critical"}) == "critical"
        assert _classify_severity({"severity": "HIGH"}) == "high"
        assert _classify_severity({"severity": "Medium"}) == "medium"
        assert _classify_severity({"severity": "low"}) == "low"
        assert _classify_severity({"severity": "info"}) == "info"

    def test_fallback_to_confidence(self):
        from vulnpredict.formatters.html import _classify_severity

        assert _classify_severity({"confidence": "high"}) == "high"
        assert _classify_severity({"confidence": "medium"}) == "medium"

    def test_default_medium(self):
        from vulnpredict.formatters.html import _classify_severity

        assert _classify_severity({}) == "medium"


class TestChartData:
    """Tests for chart data helpers."""

    def test_severity_chart_data(self):
        from vulnpredict.formatters.html import _severity_chart_data

        data = _severity_chart_data(SAMPLE_FINDINGS)
        assert "Critical" in data["labels"]
        assert "High" in data["labels"]
        assert len(data["labels"]) == len(data["values"])
        assert len(data["labels"]) == len(data["colors"])

    def test_file_chart_data(self):
        from vulnpredict.formatters.html import _file_chart_data

        data = _file_chart_data(SAMPLE_FINDINGS)
        assert "server.py" in data["labels"]
        assert "helpers.py" in data["labels"]

    def test_type_chart_data(self):
        from vulnpredict.formatters.html import _type_chart_data

        data = _type_chart_data(SAMPLE_FINDINGS)
        assert "sql_injection" in data["labels"]
        assert len(data["labels"]) == len(data["values"])

    def test_empty_findings_chart_data(self):
        from vulnpredict.formatters.html import _severity_chart_data

        data = _severity_chart_data([])
        assert data["labels"] == []
        assert data["values"] == []


class TestRemediation:
    """Tests for _get_remediation helper."""

    def test_known_types(self):
        from vulnpredict.formatters.html import _get_remediation

        assert "ast.literal_eval" in _get_remediation({"type": "eval_usage"})
        assert "parameterized" in _get_remediation({"type": "sql_injection"})
        assert "environment variables" in _get_remediation({"type": "hardcoded_secret"})
        assert "shell=True" in _get_remediation({"type": "subprocess_injection"})

    def test_unknown_type_fallback(self):
        from vulnpredict.formatters.html import _get_remediation

        result = _get_remediation({"type": "unknown_type_xyz"})
        assert "security controls" in result
