"""Tests for the automated training data pipeline."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from vulnpredict.training_pipeline import (
    CWE_TO_RULE,
    SAFE_TEMPLATES,
    VULN_TEMPLATES,
    generate_full_dataset,
    generate_synthetic_samples,
    map_cwe_to_rule,
    run_pipeline,
)


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

class TestCWEMapping:
    def test_known_cwe_returns_rule(self):
        result = map_cwe_to_rule("CWE-89")
        assert result is not None
        assert result["rule_id"] == "VP-PY-001"
        assert result["type"] == "sql_injection"
        assert result["severity"] == "critical"

    def test_unknown_cwe_returns_none(self):
        assert map_cwe_to_rule("CWE-99999") is None

    def test_all_mappings_have_required_fields(self):
        for cwe_id, rule in CWE_TO_RULE.items():
            assert "rule_id" in rule, f"{cwe_id} missing rule_id"
            assert "type" in rule, f"{cwe_id} missing type"
            assert "severity" in rule, f"{cwe_id} missing severity"
            assert rule["severity"] in ("critical", "high", "medium", "low")

    def test_mapping_covers_owasp_top_10(self):
        """Verify coverage of key CWE categories."""
        critical_cwes = ["CWE-89", "CWE-78", "CWE-79", "CWE-502"]
        for cwe in critical_cwes:
            assert cwe in CWE_TO_RULE, f"Missing mapping for {cwe}"


# ---------------------------------------------------------------------------
# Synthetic sample generation
# ---------------------------------------------------------------------------

class TestSyntheticSamples:
    def test_generates_correct_count(self):
        samples = generate_synthetic_samples("sql_injection", count=10, seed=42)
        assert len(samples) == 10

    def test_balanced_labels(self):
        samples = generate_synthetic_samples("sql_injection", count=20, seed=42)
        vuln = sum(1 for s in samples if s["label"] == 1)
        safe = sum(1 for s in samples if s["label"] == 0)
        assert vuln == 10
        assert safe == 10

    def test_sample_structure(self):
        samples = generate_synthetic_samples("xss", count=4, seed=42)
        for sample in samples:
            assert "code" in sample
            assert "label" in sample
            assert "type" in sample
            assert "source" in sample
            assert sample["type"] == "xss"
            assert sample["source"] == "synthetic"
            assert sample["label"] in (0, 1)
            assert len(sample["code"]) > 0

    def test_unknown_type_returns_empty(self):
        samples = generate_synthetic_samples("nonexistent_type", count=5)
        assert samples == []

    def test_reproducibility_with_seed(self):
        s1 = generate_synthetic_samples("sql_injection", count=10, seed=123)
        s2 = generate_synthetic_samples("sql_injection", count=10, seed=123)
        for a, b in zip(s1, s2):
            assert a["code"] == b["code"]
            assert a["label"] == b["label"]

    def test_all_vuln_types_have_templates(self):
        for vuln_type in VULN_TEMPLATES:
            templates = VULN_TEMPLATES[vuln_type]
            assert len(templates) > 0, f"No templates for {vuln_type}"
            for t in templates:
                assert len(t.strip()) > 0

    def test_vulnerable_samples_contain_patterns(self):
        samples = generate_synthetic_samples("sql_injection", count=10, seed=42)
        vuln_samples = [s for s in samples if s["label"] == 1]
        for s in vuln_samples:
            code = s["code"].lower()
            assert any(
                kw in code
                for kw in ["select", "execute", "query", "delete", "insert"]
            )


# ---------------------------------------------------------------------------
# Full dataset generation
# ---------------------------------------------------------------------------

class TestGenerateFullDataset:
    def test_creates_csv(self, tmp_path):
        output = str(tmp_path / "dataset.csv")
        metadata = generate_full_dataset(output, samples_per_type=4, seed=42)

        assert Path(output).exists()
        assert metadata["total_samples"] > 0
        assert len(metadata["vuln_types"]) == len(VULN_TEMPLATES)

    def test_csv_is_valid(self, tmp_path):
        output = str(tmp_path / "dataset.csv")
        generate_full_dataset(output, samples_per_type=4, seed=42)

        with open(output, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) > 0
        for row in rows:
            assert "code" in row
            assert "label" in row
            assert row["label"] in ("0", "1")
            assert "type" in row

    def test_metadata_sidecar(self, tmp_path):
        output = str(tmp_path / "dataset.csv")
        generate_full_dataset(output, samples_per_type=4, seed=42)

        meta_path = Path(output).with_suffix(".meta.json")
        assert meta_path.exists()

        with open(meta_path) as f:
            meta = json.load(f)

        assert "total_samples" in meta
        assert "label_distribution" in meta
        assert meta["seed"] == 42

    def test_label_distribution(self, tmp_path):
        output = str(tmp_path / "dataset.csv")
        metadata = generate_full_dataset(output, samples_per_type=10, seed=42)

        dist = metadata["label_distribution"]
        assert dist["vulnerable"] > 0
        assert dist["safe"] > 0
        assert dist["vulnerable"] + dist["safe"] == metadata["total_samples"]


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_creates_all_artifacts(self, tmp_path):
        out_dir = str(tmp_path / "training_data")
        summary = run_pipeline(
            output_dir=out_dir, samples_per_type=4, seed=42
        )

        assert Path(out_dir, "cwe_mapping.json").exists()
        assert Path(out_dir, "training_dataset.csv").exists()
        assert Path(out_dir, "training_dataset.meta.json").exists()
        assert Path(out_dir, "pipeline_summary.json").exists()

    def test_summary_structure(self, tmp_path):
        out_dir = str(tmp_path / "training_data")
        summary = run_pipeline(
            output_dir=out_dir, samples_per_type=4, seed=42
        )

        assert "pipeline_version" in summary
        assert "dataset_metadata" in summary
        assert "run_at" in summary

    def test_cwe_mapping_file(self, tmp_path):
        out_dir = str(tmp_path / "training_data")
        run_pipeline(output_dir=out_dir, samples_per_type=4, seed=42)

        with open(Path(out_dir, "cwe_mapping.json")) as f:
            mapping = json.load(f)

        assert "CWE-89" in mapping
        assert mapping["CWE-89"]["type"] == "sql_injection"

    def test_idempotent_with_same_seed(self, tmp_path):
        out1 = str(tmp_path / "run1")
        out2 = str(tmp_path / "run2")

        run_pipeline(output_dir=out1, samples_per_type=4, seed=42)
        run_pipeline(output_dir=out2, samples_per_type=4, seed=42)

        with open(Path(out1, "training_dataset.csv")) as f1, \
             open(Path(out2, "training_dataset.csv")) as f2:
            assert f1.read() == f2.read()
