"""Unit tests for vulnpredict/formatters/json_fmt.py.

Tests cover:
- JSON schema structure and required fields
- Metadata (version, timestamp, scan path, duration, file count)
- Summary (total findings, severity breakdown)
- Finding normalization for all finding types
- Severity classification (ML score and heuristic)
- Pretty-print vs compact output
- write_json file output
"""

import json
import os
import tempfile

import pytest

from vulnpredict.formatters.json_fmt import (
    SCHEMA_VERSION,
    _classify_severity,
    _normalize_finding,
    format_json,
    write_json,
)


# =========================================================================
# Sample findings for testing
# =========================================================================
TAINT_FINDING = {
    "type": "taint_analysis",
    "source": [(2, "input")],
    "sink": "eval",
    "sink_line": 5,
    "variable": "user_data",
    "trace": [(2, "input"), (5, "eval")],
    "file": "app.py",
}

INTERPROC_FINDING = {
    "type": "interprocedural_taint",
    "source_func": "get_input",
    "sink_func": "process",
    "sink": "exec",
    "sink_line": 10,
    "tainted_var": "cmd",
    "call_chain": ["get_input", "process"],
    "var_trace": [{"cmd"}],
}

DANGEROUS_FUNC_FINDING = {
    "type": "dangerous_function",
    "function": "eval",
    "line": 15,
    "file": "utils.py",
}

SECRET_FINDING = {
    "type": "hardcoded_secret",
    "variable": "API_KEY",
    "line": 3,
    "file": "config.py",
}

COMPLEXITY_FINDING = {
    "type": "high_complexity",
    "complexity": 25,
    "line": 1,
    "file": "complex.py",
}

SCORED_FINDING = {
    "type": "taint_analysis",
    "source": [(1, "input")],
    "sink": "eval",
    "sink_line": 3,
    "variable": "x",
    "trace": [(1, "input"), (3, "eval")],
    "vuln_score": 0.92,
}


# =========================================================================
# Test: format_json schema structure
# =========================================================================
class TestJsonSchema:
    """Verify the top-level JSON schema structure."""

    def test_has_schema_field(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert result["$schema"] == "vulnpredict-json-v1"

    def test_has_schema_version(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert result["schema_version"] == SCHEMA_VERSION

    def test_has_metadata_section(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert "metadata" in result
        assert result["metadata"]["tool"] == "vulnpredict"

    def test_has_summary_section(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert "summary" in result
        assert "total_findings" in result["summary"]
        assert "by_severity" in result["summary"]

    def test_has_findings_array(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert "findings" in result
        assert isinstance(result["findings"], list)


# =========================================================================
# Test: Metadata
# =========================================================================
class TestMetadata:
    """Verify metadata fields are populated correctly."""

    def test_scan_path_included(self):
        result = json.loads(format_json([], "/my/project"))
        assert result["metadata"]["scan_path"] == "/my/project"

    def test_timestamp_is_iso_format(self):
        result = json.loads(format_json([], "/tmp/test"))
        ts = result["metadata"]["scan_timestamp"]
        assert "T" in ts  # ISO format has T separator

    def test_version_is_string(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert isinstance(result["metadata"]["version"], str)

    def test_scan_duration_included_when_provided(self):
        result = json.loads(format_json([], "/tmp/test", scan_duration=1.234))
        assert result["metadata"]["scan_duration_seconds"] == 1.234

    def test_scan_duration_omitted_when_not_provided(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert "scan_duration_seconds" not in result["metadata"]

    def test_file_count_included_when_provided(self):
        result = json.loads(format_json([], "/tmp/test", file_count=42))
        assert result["metadata"]["files_scanned"] == 42

    def test_file_count_omitted_when_not_provided(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert "files_scanned" not in result["metadata"]


# =========================================================================
# Test: Summary
# =========================================================================
class TestSummary:
    """Verify summary section is computed correctly."""

    def test_empty_findings_summary(self):
        result = json.loads(format_json([], "/tmp/test"))
        assert result["summary"]["total_findings"] == 0
        assert result["summary"]["by_severity"]["high"] == 0
        assert result["summary"]["by_severity"]["medium"] == 0
        assert result["summary"]["by_severity"]["low"] == 0

    def test_findings_count_matches(self):
        findings = [TAINT_FINDING, DANGEROUS_FUNC_FINDING, SECRET_FINDING]
        result = json.loads(format_json(findings, "/tmp/test"))
        assert result["summary"]["total_findings"] == 3

    def test_severity_breakdown_sums_to_total(self):
        findings = [TAINT_FINDING, DANGEROUS_FUNC_FINDING, SECRET_FINDING, COMPLEXITY_FINDING]
        result = json.loads(format_json(findings, "/tmp/test"))
        by_sev = result["summary"]["by_severity"]
        assert by_sev["high"] + by_sev["medium"] + by_sev["low"] == result["summary"]["total_findings"]


# =========================================================================
# Test: Finding normalization
# =========================================================================
class TestFindingNormalization:
    """Verify findings are normalized into the stable output structure."""

    def test_taint_finding_normalized(self):
        normalized = _normalize_finding(TAINT_FINDING, 1)
        assert normalized["id"] == "VP-0001"
        assert normalized["type"] == "taint_analysis"
        assert normalized["severity"] == "high"
        assert "eval" in normalized["message"]
        assert normalized["sink"] == "eval"
        assert normalized["variable"] == "user_data"
        assert normalized["file"] == "app.py"

    def test_interprocedural_finding_normalized(self):
        normalized = _normalize_finding(INTERPROC_FINDING, 2)
        assert normalized["id"] == "VP-0002"
        assert normalized["type"] == "interprocedural_taint"
        assert normalized["severity"] == "high"
        assert "call_chain" in normalized

    def test_dangerous_function_normalized(self):
        normalized = _normalize_finding(DANGEROUS_FUNC_FINDING, 3)
        assert normalized["type"] == "dangerous_function"
        assert normalized["function"] == "eval"
        assert normalized["line"] == 15

    def test_secret_finding_normalized(self):
        normalized = _normalize_finding(SECRET_FINDING, 4)
        assert normalized["type"] == "hardcoded_secret"
        assert normalized["severity"] == "high"
        assert "API_KEY" in normalized["message"]

    def test_complexity_finding_normalized(self):
        normalized = _normalize_finding(COMPLEXITY_FINDING, 5)
        assert normalized["type"] == "high_complexity"
        assert normalized["complexity"] == 25

    def test_ml_score_preserved_as_confidence(self):
        normalized = _normalize_finding(SCORED_FINDING, 1)
        assert normalized["confidence"] == 0.92

    def test_unknown_type_uses_str_fallback(self):
        unknown = {"type": "custom_check", "message": "Something weird"}
        normalized = _normalize_finding(unknown, 1)
        assert normalized["message"] == "Something weird"

    def test_finding_id_is_zero_padded(self):
        normalized = _normalize_finding(TAINT_FINDING, 42)
        assert normalized["id"] == "VP-0042"

    def test_filename_field_mapped_to_file(self):
        finding = {"type": "unknown", "filename": "test.py"}
        normalized = _normalize_finding(finding, 1)
        assert normalized["file"] == "test.py"


# =========================================================================
# Test: Severity classification
# =========================================================================
class TestSeverityClassification:
    """Verify severity classification logic."""

    def test_high_ml_score(self):
        assert _classify_severity({"vuln_score": 0.9}) == "high"

    def test_medium_ml_score(self):
        assert _classify_severity({"vuln_score": 0.6}) == "medium"

    def test_low_ml_score(self):
        assert _classify_severity({"vuln_score": 0.3}) == "low"

    def test_boundary_high(self):
        assert _classify_severity({"vuln_score": 0.8}) == "high"

    def test_boundary_medium(self):
        assert _classify_severity({"vuln_score": 0.5}) == "medium"

    def test_interprocedural_is_high(self):
        assert _classify_severity({"type": "interprocedural_taint"}) == "high"

    def test_eval_sink_is_high(self):
        assert _classify_severity({"sink": "eval"}) == "high"

    def test_open_sink_is_medium(self):
        assert _classify_severity({"sink": "open"}) == "medium"

    def test_hardcoded_secret_is_high(self):
        assert _classify_severity({"type": "hardcoded_secret"}) == "high"

    def test_dangerous_function_is_medium(self):
        assert _classify_severity({"type": "dangerous_function"}) == "medium"

    def test_unknown_type_is_low(self):
        assert _classify_severity({"type": "something_else"}) == "low"


# =========================================================================
# Test: Output format (pretty vs compact)
# =========================================================================
class TestOutputFormat:
    """Verify pretty-print and compact output modes."""

    def test_pretty_print_has_indentation(self):
        result = format_json([TAINT_FINDING], "/tmp/test")
        assert "\n" in result
        assert "  " in result

    def test_compact_has_no_indentation(self):
        result = format_json([TAINT_FINDING], "/tmp/test", compact=True)
        assert "\n" not in result

    def test_both_formats_are_valid_json(self):
        pretty = format_json([TAINT_FINDING], "/tmp/test")
        compact = format_json([TAINT_FINDING], "/tmp/test", compact=True)
        json.loads(pretty)
        json.loads(compact)

    def test_both_formats_have_same_data(self):
        pretty = json.loads(format_json([TAINT_FINDING], "/tmp/test"))
        compact = json.loads(format_json([TAINT_FINDING], "/tmp/test", compact=True))
        # Remove timestamp since it differs
        del pretty["metadata"]["scan_timestamp"]
        del compact["metadata"]["scan_timestamp"]
        assert pretty == compact


# =========================================================================
# Test: write_json file output
# =========================================================================
class TestWriteJson:
    """Verify write_json writes valid JSON to a file."""

    def test_writes_valid_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            write_json([TAINT_FINDING], "/tmp/test", tmppath)
            with open(tmppath) as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 1
        finally:
            os.unlink(tmppath)

    def test_writes_compact_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            write_json([TAINT_FINDING], "/tmp/test", tmppath, compact=True)
            with open(tmppath) as f:
                content = f.read().strip()
            assert "\n" not in content.rstrip("\n")
        finally:
            os.unlink(tmppath)

    def test_file_ends_with_newline(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            write_json([], "/tmp/test", tmppath)
            with open(tmppath) as f:
                content = f.read()
            assert content.endswith("\n")
        finally:
            os.unlink(tmppath)

    def test_includes_duration_and_file_count(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            write_json([], "/tmp/test", tmppath, scan_duration=2.5, file_count=10)
            with open(tmppath) as f:
                data = json.load(f)
            assert data["metadata"]["scan_duration_seconds"] == 2.5
            assert data["metadata"]["files_scanned"] == 10
        finally:
            os.unlink(tmppath)
