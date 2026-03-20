"""Tests for the performance benchmarking module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnpredict.perf_benchmark import (
    TARGETS,
    PerfResult,
    generate_synthetic_project,
    run_perf_benchmarks,
)


# ---------------------------------------------------------------------------
# PerfResult
# ---------------------------------------------------------------------------

class TestPerfResult:
    def test_to_dict(self):
        r = PerfResult(
            scenario="small_quick",
            file_count=50,
            profile="quick",
            elapsed_seconds=2.5,
            target_seconds=5.0,
            passed=True,
            files_per_second=20.0,
        )
        d = r.to_dict()
        assert d["scenario"] == "small_quick"
        assert d["passed"] is True
        assert d["elapsed_seconds"] == 2.5

    def test_pass_fail(self):
        r_pass = PerfResult(
            scenario="test", file_count=10, profile="quick",
            elapsed_seconds=1.0, target_seconds=5.0, passed=True,
        )
        r_fail = PerfResult(
            scenario="test", file_count=10, profile="quick",
            elapsed_seconds=10.0, target_seconds=5.0, passed=False,
        )
        assert r_pass.passed is True
        assert r_fail.passed is False


# ---------------------------------------------------------------------------
# generate_synthetic_project
# ---------------------------------------------------------------------------

class TestGenerateSyntheticProject:
    def test_creates_python_files(self, tmp_path):
        project = generate_synthetic_project(
            str(tmp_path / "proj"),
            num_python_files=5,
            num_js_files=0,
            num_go_files=0,
        )
        py_files = list(Path(project).rglob("*.py"))
        assert len(py_files) == 5

    def test_creates_js_files(self, tmp_path):
        project = generate_synthetic_project(
            str(tmp_path / "proj"),
            num_python_files=0,
            num_js_files=3,
            num_go_files=0,
        )
        js_files = list(Path(project).rglob("*.js"))
        assert len(js_files) == 3

    def test_creates_go_files(self, tmp_path):
        project = generate_synthetic_project(
            str(tmp_path / "proj"),
            num_python_files=0,
            num_js_files=0,
            num_go_files=2,
        )
        go_files = list(Path(project).rglob("*.go"))
        assert len(go_files) == 2

    def test_mixed_project(self, tmp_path):
        project = generate_synthetic_project(
            str(tmp_path / "proj"),
            num_python_files=3,
            num_js_files=2,
            num_go_files=1,
        )
        all_files = (
            list(Path(project).rglob("*.py"))
            + list(Path(project).rglob("*.js"))
            + list(Path(project).rglob("*.go"))
        )
        assert len(all_files) == 6

    def test_files_have_content(self, tmp_path):
        project = generate_synthetic_project(
            str(tmp_path / "proj"),
            num_python_files=2,
            num_js_files=1,
            num_go_files=0,
            lines_per_file=20,
        )
        for f in Path(project).rglob("*.py"):
            content = f.read_text()
            assert len(content.strip()) > 0

    def test_reproducibility(self, tmp_path):
        p1 = generate_synthetic_project(
            str(tmp_path / "proj1"),
            num_python_files=3, num_js_files=0, num_go_files=0, seed=42,
        )
        p2 = generate_synthetic_project(
            str(tmp_path / "proj2"),
            num_python_files=3, num_js_files=0, num_go_files=0, seed=42,
        )
        files1 = sorted(Path(p1).rglob("*.py"))
        files2 = sorted(Path(p2).rglob("*.py"))
        for f1, f2 in zip(files1, files2):
            assert f1.read_text() == f2.read_text()


# ---------------------------------------------------------------------------
# run_perf_benchmarks
# ---------------------------------------------------------------------------

class TestRunPerfBenchmarks:
    def test_runs_small_quick(self, tmp_path):
        """Run only the small_quick scenario to keep test fast."""
        output = str(tmp_path / "results.json")
        results = run_perf_benchmarks(
            output_path=output,
            scenarios=["small_quick"],
        )
        assert len(results) == 1
        assert results[0].scenario == "small_quick"
        assert results[0].file_count == 50
        assert results[0].elapsed_seconds > 0

    def test_writes_json_output(self, tmp_path):
        output = str(tmp_path / "results.json")
        run_perf_benchmarks(
            output_path=output,
            scenarios=["small_quick"],
        )
        assert Path(output).exists()
        with open(output) as f:
            data = json.load(f)
        assert "results" in data
        assert "all_passed" in data

    def test_unknown_scenario_skipped(self, tmp_path):
        results = run_perf_benchmarks(scenarios=["nonexistent_scenario"])
        assert len(results) == 0

    def test_targets_defined(self):
        assert "small_quick" in TARGETS
        assert "small_standard" in TARGETS
        assert "medium_quick" in TARGETS
        assert "medium_standard" in TARGETS
        for name, target in TARGETS.items():
            assert "files" in target
            assert "target_seconds" in target
            assert "profile" in target
