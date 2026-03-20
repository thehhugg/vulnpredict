"""Comprehensive tests for the finding suppression module."""

import json
import os
import tempfile

import pytest

from vulnpredict.suppression import (
    IgnoreFile,
    apply_suppressions,
    filter_by_baseline,
    load_baseline,
    parse_inline_suppressions,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "suppression")


@pytest.fixture(autouse=True)
def _create_fixtures_dir():
    """Ensure the suppression fixtures directory exists."""
    os.makedirs(FIXTURES_DIR, exist_ok=True)


@pytest.fixture
def py_with_ignore_rule():
    """Python file with vulnpredict-ignore: RULE_ID comments."""
    path = os.path.join(FIXTURES_DIR, "ignore_rule.py")
    with open(path, "w") as f:
        f.write(
            'password = "secret123"  # vulnpredict-ignore: HARDCODED_SECRET\n'
            'api_key = "abc"  # vulnpredict-ignore: HARDCODED_SECRET, SENSITIVE_VAR\n'
            "normal_line = 42\n"
        )
    return path


@pytest.fixture
def py_with_ignore_line():
    """Python file with vulnpredict-ignore-line comments."""
    path = os.path.join(FIXTURES_DIR, "ignore_line.py")
    with open(path, "w") as f:
        f.write(
            'eval(user_input)  # vulnpredict-ignore-line\n'
            "safe_code = 1 + 2\n"
            'exec(cmd)  # vulnpredict-ignore-line\n'
        )
    return path


@pytest.fixture
def js_with_ignore():
    """JavaScript file with JS-style suppression comments."""
    path = os.path.join(FIXTURES_DIR, "ignore.js")
    with open(path, "w") as f:
        f.write(
            'eval(input); // vulnpredict-ignore: EVAL_USAGE\n'
            "var x = 1;\n"
            'document.write(data); // vulnpredict-ignore-line\n'
        )
    return path


@pytest.fixture
def sample_findings():
    """Sample findings list for testing."""
    return [
        {
            "file": "src/app.py",
            "line": 10,
            "rule_id": "HARDCODED_SECRET",
            "type": "hardcoded_secret",
            "message": "Hardcoded password found",
        },
        {
            "file": "src/app.py",
            "line": 20,
            "rule_id": "EVAL_USAGE",
            "type": "eval_usage",
            "message": "Use of eval()",
        },
        {
            "file": "tests/test_app.py",
            "line": 5,
            "rule_id": "HARDCODED_SECRET",
            "type": "hardcoded_secret",
            "message": "Hardcoded API key in test",
        },
        {
            "file": "build/output.py",
            "line": 1,
            "rule_id": "EVAL_USAGE",
            "type": "eval_usage",
            "message": "eval in build output",
        },
    ]


# ===========================================================================
# Tests: parse_inline_suppressions
# ===========================================================================


class TestParseInlineSuppressions:
    """Tests for parsing inline suppression comments."""

    def test_python_ignore_rule(self, py_with_ignore_rule):
        rule_supps, line_supps = parse_inline_suppressions(py_with_ignore_rule)
        assert 1 in rule_supps
        assert "HARDCODED_SECRET" in rule_supps[1]
        assert 2 in rule_supps
        assert "HARDCODED_SECRET" in rule_supps[2]
        assert "SENSITIVE_VAR" in rule_supps[2]
        assert 3 not in rule_supps
        assert len(line_supps) == 0

    def test_python_ignore_line(self, py_with_ignore_line):
        rule_supps, line_supps = parse_inline_suppressions(py_with_ignore_line)
        assert 1 in line_supps
        assert 3 in line_supps
        assert 2 not in line_supps
        assert len(rule_supps) == 0

    def test_js_ignore_rule(self, js_with_ignore):
        rule_supps, line_supps = parse_inline_suppressions(js_with_ignore)
        assert 1 in rule_supps
        assert "EVAL_USAGE" in rule_supps[1]
        assert 3 in line_supps

    def test_nonexistent_file(self):
        rule_supps, line_supps = parse_inline_suppressions("/nonexistent/file.py")
        assert rule_supps == {}
        assert line_supps == set()

    def test_empty_file(self):
        path = os.path.join(FIXTURES_DIR, "empty.py")
        with open(path, "w") as f:
            f.write("")
        rule_supps, line_supps = parse_inline_suppressions(path)
        assert rule_supps == {}
        assert line_supps == set()

    def test_case_insensitive_marker(self):
        path = os.path.join(FIXTURES_DIR, "case_insensitive.py")
        with open(path, "w") as f:
            f.write('x = 1  # VulnPredict-Ignore: MY_RULE\n')
            f.write('y = 2  # VULNPREDICT-IGNORE-LINE\n')
        rule_supps, line_supps = parse_inline_suppressions(path)
        assert 1 in rule_supps
        assert "MY_RULE" in rule_supps[1]
        assert 2 in line_supps


# ===========================================================================
# Tests: IgnoreFile
# ===========================================================================


class TestIgnoreFile:
    """Tests for .vulnpredictignore file handling."""

    def test_from_file_loads_patterns(self):
        path = os.path.join(FIXTURES_DIR, ".vulnpredictignore")
        with open(path, "w") as f:
            f.write("# Comment\n\nbuild/\n*.log\ntest_*.py\n")
        ignore = IgnoreFile.from_file(path)
        assert len(ignore.patterns) == 3
        assert "build/" in ignore.patterns
        assert "*.log" in ignore.patterns
        assert "test_*.py" in ignore.patterns

    def test_from_file_nonexistent(self):
        ignore = IgnoreFile.from_file("/nonexistent/.vulnpredictignore")
        assert ignore.patterns == []

    def test_from_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_path = os.path.join(tmpdir, ".vulnpredictignore")
            with open(ignore_path, "w") as f:
                f.write("*.log\n")
            ignore = IgnoreFile.from_project(tmpdir)
            assert ignore.patterns == ["*.log"]

    def test_is_ignored_glob_pattern(self):
        ignore = IgnoreFile(["*.log", "*.tmp"])
        assert ignore.is_ignored("app.log") is True
        assert ignore.is_ignored("debug.tmp") is True
        assert ignore.is_ignored("app.py") is False

    def test_is_ignored_directory_pattern(self):
        ignore = IgnoreFile(["build/"])
        assert ignore.is_ignored("build/output.py", project_root="/project") is True
        assert ignore.is_ignored("src/app.py", project_root="/project") is False

    def test_is_ignored_with_project_root(self):
        ignore = IgnoreFile(["test_*.py"])
        assert ignore.is_ignored("/project/tests/test_app.py", project_root="/project") is True
        assert ignore.is_ignored("/project/src/app.py", project_root="/project") is False

    def test_is_ignored_double_star(self):
        ignore = IgnoreFile(["**/test_*.py"])
        assert ignore.is_ignored("deep/nested/test_foo.py") is True

    def test_empty_patterns(self):
        ignore = IgnoreFile([])
        assert ignore.is_ignored("anything.py") is False

    def test_comments_and_blanks_skipped(self):
        path = os.path.join(FIXTURES_DIR, ".vulnpredictignore_comments")
        with open(path, "w") as f:
            f.write("# This is a comment\n\n  \n*.log\n# Another comment\n")
        ignore = IgnoreFile.from_file(path)
        assert ignore.patterns == ["*.log"]


# ===========================================================================
# Tests: load_baseline
# ===========================================================================


class TestLoadBaseline:
    """Tests for loading baseline scan results."""

    def test_load_valid_baseline(self):
        baseline_data = {
            "findings": [
                {"file": "app.py", "line": 10, "rule_id": "EVAL", "message": "eval used"},
            ]
        }
        path = os.path.join(FIXTURES_DIR, "baseline.json")
        with open(path, "w") as f:
            json.dump(baseline_data, f)
        findings = load_baseline(path)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "EVAL"

    def test_load_nonexistent_baseline(self):
        findings = load_baseline("/nonexistent/baseline.json")
        assert findings == []

    def test_load_malformed_json(self):
        path = os.path.join(FIXTURES_DIR, "malformed.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        findings = load_baseline(path)
        assert findings == []

    def test_load_baseline_missing_findings_key(self):
        path = os.path.join(FIXTURES_DIR, "no_findings.json")
        with open(path, "w") as f:
            json.dump({"summary": {}}, f)
        findings = load_baseline(path)
        assert findings == []


# ===========================================================================
# Tests: filter_by_baseline
# ===========================================================================


class TestFilterByBaseline:
    """Tests for baseline comparison filtering."""

    def test_new_findings_returned(self):
        baseline = [
            {"file": "app.py", "line": 10, "rule_id": "EVAL", "message": "eval used"},
        ]
        current = [
            {"file": "app.py", "line": 10, "rule_id": "EVAL", "message": "eval used"},
            {"file": "app.py", "line": 20, "rule_id": "SQL_INJECTION", "message": "SQL injection"},
        ]
        new, known = filter_by_baseline(current, baseline)
        assert len(new) == 1
        assert new[0]["rule_id"] == "SQL_INJECTION"
        assert len(known) == 1
        assert known[0]["rule_id"] == "EVAL"

    def test_all_new_findings(self):
        new, known = filter_by_baseline(
            [{"file": "a.py", "line": 1, "rule_id": "X", "message": "x"}],
            [],
        )
        assert len(new) == 1
        assert len(known) == 0

    def test_all_known_findings(self):
        findings = [{"file": "a.py", "line": 1, "rule_id": "X", "message": "x"}]
        new, known = filter_by_baseline(findings, findings)
        assert len(new) == 0
        assert len(known) == 1

    def test_empty_current(self):
        new, known = filter_by_baseline(
            [],
            [{"file": "a.py", "line": 1, "rule_id": "X", "message": "x"}],
        )
        assert len(new) == 0
        assert len(known) == 0


# ===========================================================================
# Tests: apply_suppressions
# ===========================================================================


class TestApplySuppressions:
    """Tests for the combined suppression pipeline."""

    def test_ignore_file_suppression(self, sample_findings):
        ignore = IgnoreFile(["build/"])
        active, suppressed = apply_suppressions(
            sample_findings, project_root="/project", ignore_file=ignore
        )
        # build/output.py should be suppressed
        assert len(suppressed) == 1
        assert suppressed[0]["file"] == "build/output.py"
        assert suppressed[0]["suppression_reason"] == "ignore_file"
        assert len(active) == 3

    def test_inline_ignore_line(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "app.py")
            with open(src, "w") as f:
                f.write('eval(x)  # vulnpredict-ignore-line\n')
                f.write('exec(y)\n')

            findings = [
                {"file": "app.py", "line": 1, "rule_id": "EVAL", "message": "eval"},
                {"file": "app.py", "line": 2, "rule_id": "EXEC", "message": "exec"},
            ]
            active, suppressed = apply_suppressions(
                findings, project_root=tmpdir
            )
            assert len(suppressed) == 1
            assert suppressed[0]["suppression_reason"] == "inline_ignore_line"
            assert len(active) == 1

    def test_inline_ignore_rule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "app.py")
            with open(src, "w") as f:
                f.write('password = "x"  # vulnpredict-ignore: HARDCODED_SECRET\n')

            findings = [
                {"file": "app.py", "line": 1, "rule_id": "HARDCODED_SECRET", "message": "secret"},
            ]
            active, suppressed = apply_suppressions(
                findings, project_root=tmpdir
            )
            assert len(suppressed) == 1
            assert suppressed[0]["suppression_reason"] == "inline_ignore_rule"
            assert len(active) == 0

    def test_inline_ignore_rule_no_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "app.py")
            with open(src, "w") as f:
                f.write('password = "x"  # vulnpredict-ignore: OTHER_RULE\n')

            findings = [
                {"file": "app.py", "line": 1, "rule_id": "HARDCODED_SECRET", "message": "secret"},
            ]
            active, suppressed = apply_suppressions(
                findings, project_root=tmpdir
            )
            assert len(active) == 1
            assert len(suppressed) == 0

    def test_baseline_suppression(self, sample_findings):
        baseline = [sample_findings[0].copy()]  # First finding is in baseline
        active, suppressed = apply_suppressions(
            sample_findings, baseline=baseline
        )
        baseline_suppressed = [s for s in suppressed if s.get("suppression_reason") == "baseline"]
        assert len(baseline_suppressed) == 1
        assert baseline_suppressed[0]["rule_id"] == "HARDCODED_SECRET"
        assert baseline_suppressed[0]["line"] == 10

    def test_combined_suppressions(self):
        """Test that all suppression mechanisms work together."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a source file with inline suppression
            src = os.path.join(tmpdir, "app.py")
            with open(src, "w") as f:
                f.write('eval(x)  # vulnpredict-ignore-line\n')
                f.write('exec(y)\n')
                f.write('password = "x"\n')

            # Create ignore file
            ignore = IgnoreFile(["build/"])

            # Baseline
            baseline = [
                {"file": "app.py", "line": 2, "rule_id": "EXEC", "message": "exec"},
            ]

            findings = [
                {"file": "app.py", "line": 1, "rule_id": "EVAL", "message": "eval"},
                {"file": "app.py", "line": 2, "rule_id": "EXEC", "message": "exec"},
                {"file": "app.py", "line": 3, "rule_id": "SECRET", "message": "secret"},
                {"file": "build/out.py", "line": 1, "rule_id": "EVAL", "message": "eval"},
            ]

            active, suppressed = apply_suppressions(
                findings,
                project_root=tmpdir,
                ignore_file=ignore,
                baseline=baseline,
            )

            # build/out.py suppressed by ignore file
            # line 1 suppressed by inline ignore-line
            # line 2 suppressed by baseline
            # line 3 is active
            assert len(active) == 1
            assert active[0]["line"] == 3
            assert len(suppressed) == 3

    def test_no_suppressions_applied(self, sample_findings):
        active, suppressed = apply_suppressions(sample_findings)
        assert len(active) == 4
        assert len(suppressed) == 0

    def test_findings_without_file_or_line(self):
        """Findings without file/line should pass through unsuppressed."""
        findings = [
            {"rule_id": "GENERAL", "message": "General finding"},
        ]
        active, suppressed = apply_suppressions(findings)
        assert len(active) == 1
        assert len(suppressed) == 0
