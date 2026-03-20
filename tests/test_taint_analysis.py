"""Unit tests for the basic taint analysis in vulnpredict/py_analyzer.py.

Tests cover:
- Source-to-sink detection (input -> eval, request.args -> cursor.execute)
- False positive prevention (safe code with no taint sources)
- Multiple taint sources and sinks
- Finding structure and metadata
"""

import os
import tempfile

import pytest

from vulnpredict.py_analyzer import taint_analysis

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "taint")


class TestTaintSourceToSink:
    """Verify that taint flows from source to sink are detected."""

    def test_input_to_eval_detected(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        sinks = [f["sink"] for f in findings]
        assert "eval" in sinks

    def test_finding_has_correct_type(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert all(f["type"] == "taint_analysis" for f in findings)

    def test_finding_has_variable_name(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        assert findings[0]["variable"] == "user_data"

    def test_finding_has_sink_line(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        assert "sink_line" in findings[0]
        assert isinstance(findings[0]["sink_line"], int)

    def test_finding_has_trace(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        assert "trace" in findings[0]
        assert len(findings[0]["trace"]) >= 2  # source + sink


class TestTaintRequestToSql:
    """Verify request.args -> cursor.execute is detected.

    Note: The taint tracker matches exact function names from TAINT_SOURCES,
    so the fixture uses request.args() (direct call) rather than
    request.args.get() (which resolves to 'request.args.get' and doesn't match).
    """

    def test_request_args_to_cursor_execute(self):
        filepath = os.path.join(FIXTURES_DIR, "request_to_sql.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        sinks = [f["sink"] for f in findings]
        assert "cursor.execute" in sinks

    def test_tainted_variable_is_query(self):
        filepath = os.path.join(FIXTURES_DIR, "request_to_sql.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        variables = [f["variable"] for f in findings]
        assert "query" in variables


class TestTaintSafeCode:
    """Verify that safe code produces no taint findings (false positive prevention)."""

    def test_no_findings_for_safe_code(self):
        filepath = os.path.join(FIXTURES_DIR, "safe_no_taint.py")
        findings = taint_analysis(filepath)
        assert len(findings) == 0


class TestTaintMultipleSources:
    """Verify multiple taint sources and sinks are detected independently."""

    def test_detects_both_sources(self):
        filepath = os.path.join(FIXTURES_DIR, "multiple_sources.py")
        findings = taint_analysis(filepath)
        variables = {f["variable"] for f in findings}
        assert "user_input" in variables
        assert "form_data" in variables

    def test_detects_both_sinks(self):
        filepath = os.path.join(FIXTURES_DIR, "multiple_sources.py")
        findings = taint_analysis(filepath)
        sinks = {f["sink"] for f in findings}
        assert "eval" in sinks
        assert "exec" in sinks

    def test_correct_number_of_findings(self):
        filepath = os.path.join(FIXTURES_DIR, "multiple_sources.py")
        findings = taint_analysis(filepath)
        assert len(findings) == 2


class TestTaintFindingStructure:
    """Verify the structure and completeness of taint findings."""

    def test_finding_has_all_required_keys(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        required_keys = {"type", "source", "sink", "sink_line", "variable", "trace"}
        for finding in findings:
            assert required_keys.issubset(finding.keys()), (
                f"Missing keys: {required_keys - finding.keys()}"
            )

    def test_source_is_list_of_tuples(self):
        filepath = os.path.join(FIXTURES_DIR, "source_to_sink.py")
        findings = taint_analysis(filepath)
        assert len(findings) >= 1
        source = findings[0]["source"]
        assert isinstance(source, list)
        assert len(source) >= 1
        # Each entry is (lineno, func_name)
        assert isinstance(source[0], (list, tuple))
        assert len(source[0]) == 2


class TestTaintSanitization:
    """Test behavior when tainted data passes through sanitization.

    Note: The current taint tracker does NOT track sanitization functions.
    It only tracks whether a variable was assigned from a taint source.
    Sanitization-aware taint tracking is a future enhancement.
    """

    def test_sanitized_input_still_flagged(self):
        """Current behavior: taint is NOT cleared by sanitization (int()).
        The tracker only checks the original assignment, not subsequent transforms."""
        filepath = os.path.join(FIXTURES_DIR, "sanitized_input.py")
        findings = taint_analysis(filepath)
        # user_data is tainted, safe_data = int(user_data) does NOT clear taint on user_data
        # But safe_data itself is NOT tainted (it's assigned from int(), not a taint source)
        variables = {f["variable"] for f in findings}
        # user_data stays tainted, but eval(safe_data) uses safe_data which is not tainted
        # So this should NOT flag safe_data, only user_data if it reaches a sink
        assert "safe_data" not in variables


class TestTaintVariableReassignment:
    """Test behavior with variable reassignment and aliasing."""

    def test_reassigned_var_still_tainted(self):
        """Current behavior: reassignment to a safe value does NOT clear taint.
        The taint tracker adds variables to the tainted set but never removes them."""
        filepath = os.path.join(FIXTURES_DIR, "variable_reassignment.py")
        findings = taint_analysis(filepath)
        # user_data was tainted by input(), then reassigned to a string literal.
        # Current implementation: taint is never cleared, so eval(user_data) is still flagged.
        variables = {f["variable"] for f in findings}
        assert "user_data" in variables  # Documents current behavior (taint not cleared)

    def test_alias_not_tracked(self):
        """Current behavior: simple assignment aliasing (alias = user_data) does NOT
        propagate taint. The tracker only taints variables assigned from taint source calls."""
        filepath = os.path.join(FIXTURES_DIR, "aliasing.py")
        findings = taint_analysis(filepath)
        # alias = user_data is a Name-to-Name assignment, not a Call assignment
        # So alias is NOT tainted in the current implementation
        variables = {f["variable"] for f in findings}
        assert "alias" not in variables  # Documents current limitation


class TestTaintErrorHandling:
    """Verify graceful handling of edge cases."""

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            taint_analysis("/nonexistent/file.py")

    def test_empty_file_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("")
            tmppath = f.name
        try:
            findings = taint_analysis(tmppath)
            assert findings == []
        finally:
            os.unlink(tmppath)

    def test_syntax_error_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def broken(\n")
            tmppath = f.name
        try:
            with pytest.raises(SyntaxError):
                taint_analysis(tmppath)
        finally:
            os.unlink(tmppath)
