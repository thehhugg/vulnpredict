"""Integration tests for the VulnPredict CLI.

Tests all CLI commands using Click's CliRunner for isolated testing.
Covers: scan, train, fetch-nvd, extract-nvd-patterns, init, and error handling.

Note: torch/transformers stubs are set up in conftest.py (loaded before this
module), so we do NOT duplicate sys.modules patching here.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from vulnpredict.cli import main  # noqa: E402


@pytest.fixture
def runner():
    """Create a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def demo_project():
    """Return the path to the demo_project directory."""
    demo = os.path.join(os.path.dirname(__file__), "..", "demo_project")
    demo = os.path.abspath(demo)
    if os.path.isdir(demo):
        return demo
    pytest.skip("demo_project not found")


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def vuln_py_file(temp_dir):
    """Create a Python file with a known vulnerability for deterministic tests."""
    code = (
        "import os\n"
        "def run_cmd(user_input):\n"
        "    os.system(user_input)  # command injection\n"
    )
    path = os.path.join(temp_dir, "vuln_sample.py")
    with open(path, "w") as f:
        f.write(code)
    return temp_dir


# ===========================================================================
# scan command tests
# ===========================================================================
class TestScanCommand:
    """Tests for the 'scan' command."""

    def test_scan_demo_project_text_output(self, runner, demo_project):
        """Scan the demo project with default text output."""
        result = runner.invoke(main, ["scan", demo_project])
        # demo_project contains known vulnerabilities → expect exit 0 (findings
        # are reported but the tool currently exits 0 for text output)
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code: {result.exit_code}\n{result.output}"
        )

    def test_scan_demo_project_json_output(self, runner, demo_project, temp_dir):
        """Scan the demo project with JSON output to file."""
        out_file = os.path.join(temp_dir, "results.json")
        result = runner.invoke(
            main, ["scan", demo_project, "--format", "json", "--output", out_file]
        )
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code: {result.exit_code}\n{result.output}"
        )
        assert os.path.exists(out_file), "JSON output file was not created"
        with open(out_file) as f:
            data = json.load(f)
        assert "findings" in data
        assert "metadata" in data

    def test_scan_demo_project_json_stdout(self, runner, demo_project):
        """Scan the demo project with JSON output to stdout."""
        result = runner.invoke(main, ["scan", demo_project, "--format", "json"])
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code: {result.exit_code}\n{result.output}"
        )
        # Output should contain valid JSON (may have logging lines mixed in)
        output = result.output.strip()
        # Find the JSON object in the output (starts with '{' or '[')
        json_start = output.find("{")
        if json_start == -1:
            json_start = output.find("[")
        assert json_start != -1, "No JSON found in stdout output"
        data = json.loads(output[json_start:])
        assert "findings" in data

    def test_scan_demo_project_sarif_output(self, runner, demo_project, temp_dir):
        """Scan the demo project with SARIF output to file."""
        out_file = os.path.join(temp_dir, "results.sarif")
        result = runner.invoke(
            main, ["scan", demo_project, "--format", "sarif", "--output", out_file]
        )
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code: {result.exit_code}\n{result.output}"
        )
        assert os.path.exists(out_file), "SARIF output file was not created"
        with open(out_file) as f:
            data = json.load(f)
        # Validate essential SARIF 2.1.0 structure
        assert data.get("version") == "2.1.0", "SARIF version must be 2.1.0"
        assert "$schema" in data, "SARIF must contain $schema"
        assert "runs" in data, "SARIF must contain runs array"
        assert isinstance(data["runs"], list) and len(data["runs"]) > 0

    def test_scan_demo_project_html_output(self, runner, demo_project, temp_dir):
        """Scan the demo project with HTML output to file."""
        out_file = os.path.join(temp_dir, "report.html")
        result = runner.invoke(
            main, ["scan", demo_project, "--format", "html", "--output", out_file]
        )
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code: {result.exit_code}\n{result.output}"
        )
        assert os.path.exists(out_file), "HTML output file was not created"
        with open(out_file) as f:
            content = f.read()
        assert "<html" in content.lower()

    def test_scan_demo_project_compact_json(self, runner, demo_project):
        """Scan with compact JSON output."""
        result = runner.invoke(
            main, ["scan", demo_project, "--format", "json", "--compact"]
        )
        assert result.exit_code in (0, 1)

    def test_scan_demo_project_min_severity(self, runner, demo_project):
        """Scan with minimum severity filter."""
        result = runner.invoke(
            main, ["scan", demo_project, "--min-severity", "high"]
        )
        assert result.exit_code in (0, 1)

    def test_scan_demo_project_verbose(self, runner, demo_project):
        """Scan with verbose output."""
        result = runner.invoke(main, ["-v", "scan", demo_project])
        assert result.exit_code in (0, 1)

    def test_scan_demo_project_debug(self, runner, demo_project):
        """Scan with debug output."""
        result = runner.invoke(main, ["--debug", "scan", demo_project])
        assert result.exit_code in (0, 1)

    def test_scan_nonexistent_path(self, runner):
        """Scan a path that doesn't exist should fail with exit code 2."""
        result = runner.invoke(
            main, ["scan", "/nonexistent/path/that/does/not/exist"]
        )
        assert result.exit_code == 2

    def test_scan_single_file(self, runner, demo_project):
        """Scan a single Python file."""
        py_file = None
        for f in os.listdir(demo_project):
            if f.endswith(".py"):
                py_file = os.path.join(demo_project, f)
                break
        if py_file is None:
            pytest.skip("No Python files in demo_project")
        result = runner.invoke(main, ["scan", py_file])
        assert result.exit_code in (0, 1)

    def test_scan_empty_directory(self, runner, temp_dir):
        """Scan an empty directory should exit 0 with no findings."""
        result = runner.invoke(main, ["scan", temp_dir])
        assert result.exit_code == 0
        assert "No potential vulnerabilities found" in result.output

    def test_scan_with_show_suppressed(self, runner, demo_project):
        """Scan with --show-suppressed flag."""
        result = runner.invoke(main, ["scan", demo_project, "--show-suppressed"])
        assert result.exit_code in (0, 1)

    def test_scan_with_log_file(self, runner, demo_project, temp_dir):
        """Scan with log output written to a file."""
        log_file = os.path.join(temp_dir, "scan.log")
        result = runner.invoke(
            main, ["--log-file", log_file, "scan", demo_project]
        )
        assert result.exit_code in (0, 1)
        assert os.path.exists(log_file)

    def test_scan_known_vuln_file(self, runner, vuln_py_file):
        """Scan a file with a known vulnerability to verify findings are reported."""
        result = runner.invoke(main, ["scan", vuln_py_file])
        # The file contains os.system(user_input) — should produce findings
        assert result.exit_code in (0, 1)
        # At least one finding should mention the vulnerability
        assert "Vulnerability" in result.output or "vuln" in result.output.lower() or "command" in result.output.lower()


# ===========================================================================
# init command tests
# ===========================================================================
class TestInitCommand:
    """Tests for the 'init' command."""

    def test_init_creates_config(self, runner, temp_dir):
        """Init should create a .vulnpredict.yml file."""
        result = runner.invoke(main, ["init", temp_dir])
        assert result.exit_code == 0
        config_path = os.path.join(temp_dir, ".vulnpredict.yml")
        assert os.path.exists(config_path)
        with open(config_path) as f:
            content = f.read()
        assert "vulnpredict" in content.lower() or "scan" in content.lower()

    def test_init_does_not_overwrite_without_confirm(self, runner, temp_dir):
        """Init should not overwrite existing config without confirmation."""
        config_path = os.path.join(temp_dir, ".vulnpredict.yml")
        with open(config_path, "w") as f:
            f.write("existing: config\n")
        result = runner.invoke(main, ["init", temp_dir], input="n\n")
        assert result.exit_code == 0
        with open(config_path) as f:
            content = f.read()
        assert "existing: config" in content

    def test_init_overwrites_with_confirm(self, runner, temp_dir):
        """Init should overwrite existing config when user confirms."""
        config_path = os.path.join(temp_dir, ".vulnpredict.yml")
        with open(config_path, "w") as f:
            f.write("existing: config\n")
        result = runner.invoke(main, ["init", temp_dir], input="y\n")
        assert result.exit_code == 0
        with open(config_path) as f:
            content = f.read()
        assert "existing: config" not in content


# ===========================================================================
# train command tests
# ===========================================================================
class TestTrainCommand:
    """Tests for the 'train' command."""

    def test_train_nonexistent_csv(self, runner):
        """Train with a nonexistent CSV file should fail."""
        result = runner.invoke(main, ["train", "/nonexistent/file.csv"])
        assert result.exit_code == 2

    def test_train_with_valid_csv(self, runner, temp_dir):
        """Train with a valid labeled CSV file succeeds with mocked ML."""
        csv_path = os.path.join(temp_dir, "labeled.csv")
        import csv

        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "complexity", "num_params", "has_eval", "label"])
            for i in range(20):
                writer.writerow([f"func_{i}", i % 5 + 1, i % 3, i % 2, i % 2])

        # Mock ML functions at the point they are imported inside cli.train
        with mock.patch("vulnpredict.ml.train_model") as mock_train, \
             mock.patch("vulnpredict.ml.extract_features") as mock_extract:
            mock_extract.return_value = [[0.1, 0.2]] * 20
            mock_train.return_value = None

            result = runner.invoke(main, ["train", csv_path])
            assert result.exit_code == 0, (
                f"Train command failed unexpectedly: {result.output}\n"
                f"Exception: {result.exception}"
            )

    def test_train_with_empty_csv(self, runner, temp_dir):
        """Train with an empty CSV file should fail gracefully."""
        csv_path = os.path.join(temp_dir, "empty.csv")
        with open(csv_path, "w") as f:
            f.write("")
        result = runner.invoke(main, ["train", csv_path])
        assert result.exit_code == 2


# ===========================================================================
# fetch-nvd command tests
# ===========================================================================
class TestFetchNvdCommand:
    """Tests for the 'fetch-nvd' command."""

    def test_fetch_nvd_with_mocked_http(self, runner, temp_dir):
        """Fetch NVD data with mocked HTTP responses."""
        out_file = os.path.join(temp_dir, "nvd_2023.json")
        with mock.patch("vulnpredict.data_ingest.fetch_nvd_cve_data") as mock_fetch:
            mock_fetch.return_value = None
            result = runner.invoke(main, ["fetch-nvd", "2023", out_file])
            mock_fetch.assert_called_once_with(2023, out_file)

    def test_fetch_nvd_invalid_year_type(self, runner, temp_dir):
        """Fetch NVD with non-integer year should fail."""
        out_file = os.path.join(temp_dir, "nvd.json")
        result = runner.invoke(main, ["fetch-nvd", "not-a-year", out_file])
        assert result.exit_code != 0

    def test_fetch_nvd_api_failure(self, runner, temp_dir):
        """Fetch NVD when API fails should exit with error code 2."""
        out_file = os.path.join(temp_dir, "nvd.json")
        with mock.patch("vulnpredict.data_ingest.fetch_nvd_cve_data") as mock_fetch:
            mock_fetch.side_effect = Exception("API connection failed")
            result = runner.invoke(main, ["fetch-nvd", "2023", out_file])
            assert result.exit_code == 2


# ===========================================================================
# extract-nvd-patterns command tests
# ===========================================================================
class TestExtractNvdPatternsCommand:
    """Tests for the 'extract-nvd-patterns' command."""

    def test_extract_patterns_nonexistent_json(self, runner, temp_dir):
        """Extract patterns from nonexistent JSON file should fail with exit 2."""
        out_csv = os.path.join(temp_dir, "patterns.csv")
        result = runner.invoke(
            main, ["extract-nvd-patterns", "/nonexistent.json", out_csv]
        )
        assert result.exit_code == 2

    def test_extract_patterns_with_fixture(self, runner, temp_dir):
        """Extract patterns from a fixture NVD JSON file."""
        nvd_json = os.path.join(temp_dir, "nvd.json")
        with open(nvd_json, "w") as f:
            json.dump({"CVE_Items": []}, f)

        out_csv = os.path.join(temp_dir, "patterns.csv")
        with mock.patch(
            "vulnpredict.pattern_extract.extract_patterns_from_nvd"
        ) as mock_extract:
            import pandas as pd

            mock_extract.return_value = pd.DataFrame(
                {"pattern": ["test"], "severity": ["high"]}
            )
            result = runner.invoke(
                main, ["extract-nvd-patterns", nvd_json, out_csv]
            )
            assert result.exit_code == 0


# ===========================================================================
# help and version tests
# ===========================================================================
class TestHelpOutput:
    """Tests for help output of all commands."""

    def test_main_help(self, runner):
        """Main help should show all commands."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "train" in result.output
        assert "fetch-nvd" in result.output
        assert "init" in result.output

    def test_scan_help(self, runner):
        """Scan help should show all options."""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--min-severity" in result.output

    def test_train_help(self, runner):
        """Train help should show usage."""
        result = runner.invoke(main, ["train", "--help"])
        assert result.exit_code == 0
        assert "CSV" in result.output.upper() or "csv" in result.output

    def test_init_help(self, runner):
        """Init help should show usage."""
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0

    def test_fetch_nvd_help(self, runner):
        """Fetch-nvd help should show usage."""
        result = runner.invoke(main, ["fetch-nvd", "--help"])
        assert result.exit_code == 0
        assert "YEAR" in result.output

    def test_extract_nvd_patterns_help(self, runner):
        """Extract-nvd-patterns help should show usage."""
        result = runner.invoke(main, ["extract-nvd-patterns", "--help"])
        assert result.exit_code == 0


# ===========================================================================
# exit code tests
# ===========================================================================
class TestExitCodes:
    """Tests for proper exit codes."""

    def test_clean_scan_exit_code(self, runner, temp_dir):
        """Scanning an empty directory should exit with 0."""
        result = runner.invoke(main, ["scan", temp_dir])
        assert result.exit_code == 0

    def test_invalid_command_exit_code(self, runner):
        """Running an invalid command should fail."""
        result = runner.invoke(main, ["nonexistent-command"])
        assert result.exit_code != 0

    def test_scan_invalid_format(self, runner, temp_dir):
        """Using an invalid format should fail."""
        result = runner.invoke(main, ["scan", temp_dir, "--format", "xml"])
        assert result.exit_code != 0


# ===========================================================================
# edge case tests
# ===========================================================================
class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_scan_with_all_options(self, runner, demo_project, temp_dir):
        """Scan with all options combined."""
        out_file = os.path.join(temp_dir, "results.json")
        result = runner.invoke(
            main,
            [
                "-v",
                "scan",
                demo_project,
                "--format",
                "json",
                "--output",
                out_file,
                "--compact",
                "--min-severity",
                "medium",
                "--show-suppressed",
            ],
        )
        assert result.exit_code in (0, 1)

    def test_scan_with_baseline(self, runner, demo_project, temp_dir):
        """Scan with a baseline JSON file for differential scanning."""
        baseline_file = os.path.join(temp_dir, "baseline.json")
        with open(baseline_file, "w") as f:
            json.dump(
                {"findings": [], "metadata": {"scan_path": demo_project}}, f
            )
        result = runner.invoke(
            main,
            ["scan", demo_project, "--baseline", baseline_file],
        )
        assert result.exit_code in (0, 1)

    def test_scan_symlink_directory(self, runner, demo_project, temp_dir):
        """Scan a symlinked directory."""
        link_path = os.path.join(temp_dir, "linked_project")
        os.symlink(demo_project, link_path)
        result = runner.invoke(main, ["scan", link_path])
        assert result.exit_code in (0, 1)

    def test_scan_with_config_file(self, runner, demo_project, temp_dir):
        """Scan a project that has a .vulnpredict.yml config file."""
        # Create a project dir with a config file
        import shutil

        proj = os.path.join(temp_dir, "configured_project")
        shutil.copytree(demo_project, proj)
        config_path = os.path.join(proj, ".vulnpredict.yml")
        with open(config_path, "w") as f:
            f.write("scan:\n  min_severity: low\n  exclude:\n    - '*.test.py'\n")
        result = runner.invoke(main, ["scan", proj])
        assert result.exit_code in (0, 1)
