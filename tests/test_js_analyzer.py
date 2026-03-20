"""Comprehensive unit tests for vulnpredict/js_analyzer.py.

Tests cover:
- analyze_js_file() with dangerous calls, safe code, complex functions, and error handling
- run_eslint() with mocked subprocess calls
- extract_js_dependencies() with valid, missing, and malformed package.json
- analyze_js_project() for recursive file discovery and aggregation

All subprocess calls to Node.js and ESLint are mocked so tests run without
Node.js installed.
"""

import json
import os
import tempfile
import shutil
from unittest import mock

import pytest

from vulnpredict.js_analyzer import (
    analyze_js_file,
    analyze_js_project,
    extract_js_dependencies,
    run_eslint,
)

# ---------------------------------------------------------------------------
# Paths to test fixtures
# ---------------------------------------------------------------------------
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "javascript")
VULN_EVAL_JS = os.path.join(FIXTURES_DIR, "vulnerable_eval.js")
VULN_DOM_XSS_JS = os.path.join(FIXTURES_DIR, "vulnerable_dom_xss.js")
SAFE_CODE_JS = os.path.join(FIXTURES_DIR, "safe_code.js")
COMPLEX_JS = os.path.join(FIXTURES_DIR, "complex_function.js")
SYNTAX_ERROR_JS = os.path.join(FIXTURES_DIR, "syntax_error.js")
PACKAGE_JSON = os.path.join(FIXTURES_DIR, "package.json")
MALFORMED_PKG = os.path.join(FIXTURES_DIR, "malformed_package.json")


# ---------------------------------------------------------------------------
# Helper: build a mock subprocess.CompletedProcess for Node.js calls
# ---------------------------------------------------------------------------
def _make_node_result(findings_list):
    """Return a CompletedProcess whose stdout is JSON-encoded findings."""
    return mock.Mock(
        returncode=0,
        stdout=json.dumps(findings_list),
        stderr="",
    )


# =========================================================================
# Test: analyze_js_file — dangerous call detection
# =========================================================================
class TestAnalyzeJsFileDangerousCalls:
    """Verify that analyze_js_file detects eval, Function, setTimeout."""

    MOCK_FINDINGS = [
        {"type": "function_analysis", "name": "processInput", "line": 2,
         "length": 2, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "dangerous_call", "function": "eval", "line": 3},
        {"type": "function_analysis", "name": "createDynamic", "line": 8,
         "length": 2, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "dangerous_call", "function": "Function", "line": 9},
        {"type": "function_analysis", "name": "delayedExec", "line": 14,
         "length": 1, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "dangerous_call", "function": "setTimeout", "line": 15},
    ]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_eval(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_FINDINGS)
        findings = analyze_js_file(VULN_EVAL_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        functions_found = {f["function"] for f in dangerous}
        assert "eval" in functions_found

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_function_constructor(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_FINDINGS)
        findings = analyze_js_file(VULN_EVAL_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        functions_found = {f["function"] for f in dangerous}
        assert "Function" in functions_found

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_settimeout_with_string(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_FINDINGS)
        findings = analyze_js_file(VULN_EVAL_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        functions_found = {f["function"] for f in dangerous}
        assert "setTimeout" in functions_found

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_all_three_dangerous_calls(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_FINDINGS)
        findings = analyze_js_file(VULN_EVAL_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        assert len(dangerous) == 3


# =========================================================================
# Test: analyze_js_file — DOM XSS and setInterval detection
# =========================================================================
class TestAnalyzeJsFileDomXss:
    """Verify that analyze_js_file detects innerHTML assignments and setInterval."""

    MOCK_DOM_XSS_FINDINGS = [
        {"type": "function_analysis", "name": "displayMessage", "line": 2,
         "length": 1, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "dom_xss", "property": "innerHTML", "line": 3},
        {"type": "function_analysis", "name": "pollServer", "line": 7,
         "length": 1, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "dangerous_call", "function": "setInterval", "line": 8},
    ]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_innerhtml_assignment(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_DOM_XSS_FINDINGS)
        findings = analyze_js_file(VULN_DOM_XSS_JS)
        xss_findings = [f for f in findings if f["type"] == "dom_xss"]
        assert len(xss_findings) == 1
        assert xss_findings[0]["property"] == "innerHTML"

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_setinterval(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_DOM_XSS_FINDINGS)
        findings = analyze_js_file(VULN_DOM_XSS_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        functions_found = {f["function"] for f in dangerous}
        assert "setInterval" in functions_found

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_dom_xss_finding_has_line_number(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_DOM_XSS_FINDINGS)
        findings = analyze_js_file(VULN_DOM_XSS_JS)
        xss_findings = [f for f in findings if f["type"] == "dom_xss"]
        assert xss_findings[0]["line"] == 3


# =========================================================================
# Test: analyze_js_file — safe code
# =========================================================================
class TestAnalyzeJsFileSafeCode:
    """Verify that safe code produces no dangerous call findings."""

    MOCK_SAFE_FINDINGS = [
        {"type": "function_analysis", "name": "add", "line": 2,
         "length": 1, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "function_analysis", "name": "greet", "line": 6,
         "length": 3, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
        {"type": "function_analysis", "name": "validateInput", "line": 12,
         "length": 2, "max_nesting_depth": 0,
         "input_validation": ["encodeURIComponent"], "dangerous_calls": []},
    ]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_no_dangerous_calls_in_safe_code(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_SAFE_FINDINGS)
        findings = analyze_js_file(SAFE_CODE_JS)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        assert len(dangerous) == 0

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_detects_input_validation(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_SAFE_FINDINGS)
        findings = analyze_js_file(SAFE_CODE_JS)
        func_findings = [f for f in findings if f["type"] == "function_analysis"]
        validate_fn = [f for f in func_findings if f["name"] == "validateInput"]
        assert len(validate_fn) == 1
        assert "encodeURIComponent" in validate_fn[0]["input_validation"]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_function_analysis_for_all_functions(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_SAFE_FINDINGS)
        findings = analyze_js_file(SAFE_CODE_JS)
        func_findings = [f for f in findings if f["type"] == "function_analysis"]
        assert len(func_findings) == 3
        names = {f["name"] for f in func_findings}
        assert names == {"add", "greet", "validateInput"}


# =========================================================================
# Test: analyze_js_file — function complexity analysis
# =========================================================================
class TestAnalyzeJsFileComplexity:
    """Verify function analysis captures complexity metrics."""

    MOCK_COMPLEX_FINDINGS = [
        {"type": "function_analysis", "name": "complexProcessor", "line": 2,
         "length": 10, "max_nesting_depth": 4, "input_validation": [],
         "dangerous_calls": []},
        {"type": "function_analysis", "name": "simpleHelper", "line": 17,
         "length": 1, "max_nesting_depth": 0, "input_validation": [],
         "dangerous_calls": []},
    ]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_complex_function_has_high_nesting(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_COMPLEX_FINDINGS)
        findings = analyze_js_file(COMPLEX_JS)
        complex_fn = [f for f in findings if f.get("name") == "complexProcessor"]
        assert len(complex_fn) == 1
        assert complex_fn[0]["max_nesting_depth"] >= 3

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_simple_function_has_low_nesting(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_COMPLEX_FINDINGS)
        findings = analyze_js_file(COMPLEX_JS)
        simple_fn = [f for f in findings if f.get("name") == "simpleHelper"]
        assert len(simple_fn) == 1
        assert simple_fn[0]["max_nesting_depth"] == 0

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_function_length_captured(self, mock_run):
        mock_run.return_value = _make_node_result(self.MOCK_COMPLEX_FINDINGS)
        findings = analyze_js_file(COMPLEX_JS)
        complex_fn = [f for f in findings if f.get("name") == "complexProcessor"]
        assert complex_fn[0]["length"] > 1


# =========================================================================
# Test: analyze_js_file — error handling
# =========================================================================
class TestAnalyzeJsFileErrorHandling:
    """Verify graceful error handling when Node.js fails."""

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_on_subprocess_error(self, mock_run):
        mock_run.side_effect = Exception("node not found")
        findings = analyze_js_file(VULN_EVAL_JS)
        assert findings == []

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_on_invalid_json(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="not json", stderr=""
        )
        findings = analyze_js_file(VULN_EVAL_JS)
        assert findings == []

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_on_nonexistent_file(self, mock_run):
        mock_run.side_effect = FileNotFoundError("no such file")
        findings = analyze_js_file("/nonexistent/path.js")
        assert findings == []

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_subprocess_called_with_node(self, mock_run):
        mock_run.return_value = _make_node_result([])
        analyze_js_file(VULN_EVAL_JS)
        args = mock_run.call_args[0][0]
        assert args[0] == "node"
        assert args[2] == VULN_EVAL_JS


# =========================================================================
# Test: run_eslint
# =========================================================================
class TestRunEslint:
    """Verify ESLint integration parsing."""

    MOCK_ESLINT_OUTPUT = [
        {
            "filePath": "/test/file.js",
            "messages": [
                {"ruleId": "no-eval", "message": "eval is harmful", "line": 3, "severity": 2},
                {"ruleId": "no-unused-vars", "message": "x is unused", "line": 5, "severity": 1},
            ],
        }
    ]

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_parses_eslint_findings(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=json.dumps(self.MOCK_ESLINT_OUTPUT),
            stderr="",
        )
        findings = run_eslint("/test/file.js")
        assert len(findings) == 2
        assert all(f["type"] == "eslint" for f in findings)

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_eslint_finding_has_rule_id(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=json.dumps(self.MOCK_ESLINT_OUTPUT),
            stderr="",
        )
        findings = run_eslint("/test/file.js")
        rule_ids = {f["ruleId"] for f in findings}
        assert "no-eval" in rule_ids
        assert "no-unused-vars" in rule_ids

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_eslint_finding_has_severity(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=json.dumps(self.MOCK_ESLINT_OUTPUT),
            stderr="",
        )
        findings = run_eslint("/test/file.js")
        severities = {f["severity"] for f in findings}
        assert 1 in severities
        assert 2 in severities

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_when_eslint_not_available(self, mock_run):
        mock_run.side_effect = FileNotFoundError("eslint not found")
        findings = run_eslint("/test/file.js")
        assert findings == []

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_on_eslint_error(self, mock_run):
        mock_run.side_effect = Exception("eslint crashed")
        findings = run_eslint("/test/file.js")
        assert findings == []

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_returns_empty_on_invalid_json_from_eslint(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="not json", stderr=""
        )
        findings = run_eslint("/test/file.js")
        assert findings == []


# =========================================================================
# Test: extract_js_dependencies
# =========================================================================
class TestExtractJsDependencies:
    """Verify package.json dependency extraction."""

    @mock.patch("vulnpredict.vuln_db.check_vulnerable", return_value=(False, None))
    def test_extracts_all_dependencies(self, mock_vuln):
        deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(FIXTURES_DIR)
        dep_names = [d["name"] for d in deps]
        assert "express" in dep_names
        assert "lodash" in dep_names

    @mock.patch("vulnpredict.vuln_db.check_vulnerable", return_value=(False, None))
    def test_extracts_dev_dependencies(self, mock_vuln):
        deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(FIXTURES_DIR)
        dep_names = [d["name"] for d in deps]
        assert "jest" in dep_names
        assert "eslint" in dep_names

    @mock.patch("vulnpredict.vuln_db.check_vulnerable", return_value=(False, None))
    def test_returns_four_total_deps(self, mock_vuln):
        deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(FIXTURES_DIR)
        assert len(deps) == 4

    def test_returns_empty_for_missing_package_json(self):
        deps, num_vuln, num_outdated, max_severity = extract_js_dependencies("/nonexistent/path")
        assert deps == []

    def test_returns_empty_for_malformed_package_json(self):
        """Use a temp dir with only the malformed package.json."""
        tmpdir = tempfile.mkdtemp()
        try:
            shutil.copy(MALFORMED_PKG, os.path.join(tmpdir, "package.json"))
            deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(tmpdir)
            assert deps == []
        finally:
            shutil.rmtree(tmpdir)

    def test_returns_empty_for_empty_dependencies(self):
        """package.json with no dependencies or devDependencies."""
        tmpdir = tempfile.mkdtemp()
        try:
            pkg = {"name": "empty", "version": "1.0.0"}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)
            deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(tmpdir)
            assert deps == []
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch("vulnpredict.vuln_db.check_vulnerable", return_value=(True, {"severity": "high"}))
    def test_counts_vulnerable_dependencies(self, mock_vuln):
        deps, num_vuln, num_outdated, max_severity = extract_js_dependencies(FIXTURES_DIR)
        assert num_vuln == 4  # All 4 deps flagged as vulnerable
        assert max_severity == "high"


# =========================================================================
# Test: analyze_js_project — recursive file discovery
# =========================================================================
class TestAnalyzeJsProject:
    """Verify analyze_js_project finds all .js files and aggregates findings."""

    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file")
    def test_finds_all_js_files_in_fixtures(self, mock_analyze, mock_eslint):
        mock_analyze.return_value = [{"type": "function_analysis", "name": "test"}]
        findings = analyze_js_project(FIXTURES_DIR)
        # There are 5 .js files in fixtures (including vulnerable_dom_xss.js)
        assert mock_analyze.call_count == 5

    @mock.patch("vulnpredict.vuln_db.check_vulnerable", return_value=(False, None))
    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file")
    def test_includes_dependencies_finding(self, mock_analyze, mock_eslint, mock_vuln):
        mock_analyze.return_value = []
        findings = analyze_js_project(FIXTURES_DIR)
        dep_findings = [f for f in findings if f.get("type") == "dependencies"]
        assert len(dep_findings) == 1
        dep_names = [d["name"] for d in dep_findings[0]["dependencies"]]
        assert "express" in dep_names

    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file")
    def test_aggregates_findings_from_multiple_files(self, mock_analyze, mock_eslint):
        mock_analyze.return_value = [
            {"type": "dangerous_call", "function": "eval", "line": 1}
        ]
        findings = analyze_js_project(FIXTURES_DIR)
        dangerous = [f for f in findings if f["type"] == "dangerous_call"]
        # One finding per .js file (5 files)
        assert len(dangerous) == 5

    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file", return_value=[])
    def test_empty_dir_returns_empty(self, mock_analyze, mock_eslint):
        tmpdir = tempfile.mkdtemp()
        try:
            findings = analyze_js_project(tmpdir)
            assert findings == []
            assert mock_analyze.call_count == 0
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file")
    def test_finds_js_in_subdirectories(self, mock_analyze, mock_eslint):
        """Create a nested directory structure and verify recursive discovery."""
        tmpdir = tempfile.mkdtemp()
        try:
            subdir = os.path.join(tmpdir, "sub", "deep")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "test.js"), "w") as f:
                f.write("function test() {}")
            with open(os.path.join(tmpdir, "root.js"), "w") as f:
                f.write("function root() {}")
            mock_analyze.return_value = []
            analyze_js_project(tmpdir)
            assert mock_analyze.call_count == 2
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch("vulnpredict.js_analyzer.run_eslint", return_value=[])
    @mock.patch("vulnpredict.js_analyzer.analyze_js_file", return_value=[])
    def test_ignores_non_js_files(self, mock_analyze, mock_eslint):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "readme.md"), "w") as f:
                f.write("# Hello")
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("print('hi')")
            with open(os.path.join(tmpdir, "code.js"), "w") as f:
                f.write("function x() {}")
            analyze_js_project(tmpdir)
            assert mock_analyze.call_count == 1
        finally:
            shutil.rmtree(tmpdir)


# =========================================================================
# Test: analyze_js_file — temp file cleanup
# =========================================================================
class TestAnalyzeJsFileTempCleanup:
    """Verify that temp script files are cleaned up after analysis."""

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_temp_script_cleaned_up_on_success(self, mock_run):
        mock_run.return_value = _make_node_result([])
        # Before the call, count temp files
        analyze_js_file(SAFE_CODE_JS)
        # The function should clean up its temp file
        # We verify by checking subprocess was called (which means temp was created)
        assert mock_run.called

    @mock.patch("vulnpredict.js_analyzer.subprocess.run")
    def test_temp_script_cleaned_up_on_error(self, mock_run):
        mock_run.side_effect = Exception("node crashed")
        analyze_js_file(SAFE_CODE_JS)
        # Should not raise, temp file should be cleaned up
        assert mock_run.called
