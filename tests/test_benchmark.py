"""Tests for the benchmark evaluation framework."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from vulnpredict.benchmark import (
    BenchmarkResult,
    BenchmarkSample,
    generate_benchmark_dataset,
    load_benchmark_dataset,
    run_benchmark,
)


# ---------------------------------------------------------------------------
# BenchmarkResult
# ---------------------------------------------------------------------------

class TestBenchmarkResult:
    def test_precision(self):
        r = BenchmarkResult(true_positives=8, false_positives=2)
        assert abs(r.precision - 0.8) < 1e-6

    def test_recall(self):
        r = BenchmarkResult(true_positives=8, false_negatives=2)
        assert abs(r.recall - 0.8) < 1e-6

    def test_f1_score(self):
        r = BenchmarkResult(true_positives=8, false_positives=2, false_negatives=2)
        expected = 2 * 0.8 * 0.8 / (0.8 + 0.8)
        assert abs(r.f1_score - expected) < 1e-6

    def test_false_positive_rate(self):
        r = BenchmarkResult(false_positives=3, true_negatives=7)
        assert abs(r.false_positive_rate - 0.3) < 1e-6

    def test_accuracy(self):
        r = BenchmarkResult(
            total_samples=10,
            true_positives=4,
            true_negatives=4,
            false_positives=1,
            false_negatives=1,
        )
        assert abs(r.accuracy - 0.8) < 1e-6

    def test_zero_division_safety(self):
        r = BenchmarkResult()
        assert r.precision == 0.0
        assert r.recall == 0.0
        assert r.f1_score == 0.0
        assert r.false_positive_rate == 0.0
        assert r.accuracy == 0.0

    def test_to_dict(self):
        r = BenchmarkResult(
            total_samples=10,
            true_positives=5,
            false_positives=1,
            true_negatives=3,
            false_negatives=1,
            elapsed_seconds=1.23,
        )
        d = r.to_dict()
        assert d["total_samples"] == 10
        assert d["true_positives"] == 5
        assert "precision" in d
        assert "recall" in d
        assert "f1_score" in d
        assert isinstance(d["precision"], float)


# ---------------------------------------------------------------------------
# load_benchmark_dataset
# ---------------------------------------------------------------------------

class TestLoadBenchmarkDataset:
    def test_loads_csv(self, tmp_path):
        csv_path = tmp_path / "benchmark.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["code", "label", "type", "cwe", "language"])
            writer.writeheader()
            writer.writerow({"code": "eval(x)", "label": "1", "type": "code_injection", "cwe": "CWE-95", "language": "python"})
            writer.writerow({"code": "json.loads(x)", "label": "0", "type": "code_injection", "cwe": "", "language": "python"})

        samples = load_benchmark_dataset(str(csv_path))
        assert len(samples) == 2
        assert samples[0].label == 1
        assert samples[0].vuln_type == "code_injection"
        assert samples[1].label == 0

    def test_handles_missing_optional_fields(self, tmp_path):
        csv_path = tmp_path / "minimal.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["code", "label", "type"])
            writer.writeheader()
            writer.writerow({"code": "x = 1", "label": "0", "type": "safe"})

        samples = load_benchmark_dataset(str(csv_path))
        assert len(samples) == 1
        assert samples[0].language == "python"  # default
        assert samples[0].cwe == ""


# ---------------------------------------------------------------------------
# generate_benchmark_dataset
# ---------------------------------------------------------------------------

class TestGenerateBenchmarkDataset:
    def test_creates_csv(self, tmp_path):
        output = str(tmp_path / "bench.csv")
        result = generate_benchmark_dataset(output, samples_per_type=4, seed=42)
        assert Path(result).exists()

    def test_csv_has_correct_columns(self, tmp_path):
        output = str(tmp_path / "bench.csv")
        generate_benchmark_dataset(output, samples_per_type=4, seed=42)

        with open(output, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) > 0
        for row in rows:
            assert "code" in row
            assert "label" in row
            assert "type" in row
            assert "language" in row

    def test_balanced_labels(self, tmp_path):
        output = str(tmp_path / "bench.csv")
        generate_benchmark_dataset(output, samples_per_type=10, seed=42)

        with open(output, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        vuln = sum(1 for r in rows if r["label"] == "1")
        safe = sum(1 for r in rows if r["label"] == "0")
        assert vuln > 0
        assert safe > 0


# ---------------------------------------------------------------------------
# run_benchmark
# ---------------------------------------------------------------------------

class TestRunBenchmark:
    def test_runs_and_returns_result(self, tmp_path):
        # Create a small benchmark dataset
        csv_path = tmp_path / "bench.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["code", "label", "type", "language"])
            writer.writeheader()
            # Vulnerable: should be detected
            writer.writerow({
                "code": "import os\nos.system('rm -rf ' + user_input)",
                "label": "1",
                "type": "command_injection",
                "language": "python",
            })
            # Safe: should not be detected
            writer.writerow({
                "code": "x = 1 + 2\nprint(x)",
                "label": "0",
                "type": "safe",
                "language": "python",
            })

        result = run_benchmark(str(csv_path))
        assert isinstance(result, BenchmarkResult)
        assert result.total_samples == 2
        assert result.elapsed_seconds > 0

    def test_writes_output_json(self, tmp_path):
        csv_path = tmp_path / "bench.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["code", "label", "type", "language"])
            writer.writeheader()
            writer.writerow({
                "code": "eval(user_input)",
                "label": "1",
                "type": "code_injection",
                "language": "python",
            })

        output_json = str(tmp_path / "results.json")
        run_benchmark(str(csv_path), output_path=output_json)

        assert Path(output_json).exists()
        with open(output_json) as f:
            data = json.load(f)
        assert "summary" in data
        assert "detailed_results" in data

    def test_per_type_tracking(self, tmp_path):
        csv_path = tmp_path / "bench.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["code", "label", "type", "language"])
            writer.writeheader()
            writer.writerow({
                "code": "import os\nos.system(cmd)",
                "label": "1",
                "type": "command_injection",
                "language": "python",
            })
            writer.writerow({
                "code": "cursor.execute('SELECT * FROM t WHERE id=' + uid)",
                "label": "1",
                "type": "sql_injection",
                "language": "python",
            })

        result = run_benchmark(str(csv_path))
        assert "command_injection" in result.per_type_results
        assert "sql_injection" in result.per_type_results

    def test_generated_dataset_benchmark(self, tmp_path):
        """End-to-end: generate dataset then run benchmark."""
        dataset = str(tmp_path / "bench.csv")
        generate_benchmark_dataset(dataset, samples_per_type=4, seed=42)

        result = run_benchmark(dataset)
        assert result.total_samples > 0
        assert result.true_positives + result.false_negatives + \
               result.true_negatives + result.false_positives == result.total_samples
