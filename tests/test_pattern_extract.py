"""Unit tests for NVD pattern extraction (vulnpredict.pattern_extract)."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict

import pandas as pd
import pytest

from vulnpredict.pattern_extract import extract_patterns_from_nvd

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
NVD_SAMPLE_PATH = os.path.join(FIXTURES_DIR, "nvd_sample.json")


# ---------------------------------------------------------------------------
# Basic extraction
# ---------------------------------------------------------------------------


class TestExtractPatternsFromNvd:
    """Tests for the extract_patterns_from_nvd function."""

    def test_returns_dataframe(self) -> None:
        """Should return a pandas DataFrame."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        assert isinstance(df, pd.DataFrame)

    def test_correct_row_count(self) -> None:
        """Should produce one row per CVE in the sample data."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        assert len(df) == 3

    def test_has_required_columns(self) -> None:
        """DataFrame should have cve_id, description, cwes, and products columns."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        expected_cols = {"cve_id", "description", "cwes", "products"}
        assert expected_cols.issubset(set(df.columns))

    def test_cve_ids_extracted(self) -> None:
        """Should extract correct CVE IDs."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        cve_ids = df["cve_id"].tolist()
        assert "CVE-2024-0001" in cve_ids
        assert "CVE-2024-0002" in cve_ids
        assert "CVE-2024-0003" in cve_ids

    def test_descriptions_extracted(self) -> None:
        """Should extract English descriptions."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        row = df[df["cve_id"] == "CVE-2024-0001"].iloc[0]
        assert "SQL injection" in row["description"]

    def test_cwes_extracted(self) -> None:
        """Should extract CWE IDs as lists."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        row = df[df["cve_id"] == "CVE-2024-0001"].iloc[0]
        assert "CWE-89" in row["cwes"]

    def test_multiple_cwes(self) -> None:
        """CVE-2024-0003 has two CWEs; both should be extracted."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        row = df[df["cve_id"] == "CVE-2024-0003"].iloc[0]
        assert "CWE-120" in row["cwes"]
        assert "CWE-787" in row["cwes"]

    def test_products_extracted(self) -> None:
        """Should extract CPE match criteria as products."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        row = df[df["cve_id"] == "CVE-2024-0001"].iloc[0]
        products = row["products"]
        assert len(products) == 2
        assert any("example:product:1.0" in p for p in products)
        assert any("example:product:1.1" in p for p in products)

    def test_no_configurations_gives_empty_products(self) -> None:
        """CVE-2024-0003 has no configurations; products should be empty."""
        df = extract_patterns_from_nvd(NVD_SAMPLE_PATH)
        row = df[df["cve_id"] == "CVE-2024-0003"].iloc[0]
        assert row["products"] == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestExtractPatternsEdgeCases:
    """Edge case tests for pattern extraction."""

    def test_empty_vulnerabilities_list(self) -> None:
        """Empty vulnerabilities array should produce an empty DataFrame."""
        data: Dict[str, Any] = {"vulnerabilities": []}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            df = extract_patterns_from_nvd(path)
            assert isinstance(df, pd.DataFrame)
            assert len(df) == 0
        finally:
            os.unlink(path)

    def test_missing_vulnerabilities_key(self) -> None:
        """Missing 'vulnerabilities' key should produce an empty DataFrame."""
        data: Dict[str, Any] = {"format": "NVD_CVE"}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            df = extract_patterns_from_nvd(path)
            assert isinstance(df, pd.DataFrame)
            assert len(df) == 0
        finally:
            os.unlink(path)

    def test_cve_with_missing_fields(self) -> None:
        """CVE with minimal fields should not crash."""
        data: Dict[str, Any] = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-9999"}}
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            df = extract_patterns_from_nvd(path)
            assert len(df) == 1
            assert df["cve_id"].iloc[0] == "CVE-2024-9999"
            assert df["description"].iloc[0] == ""
        finally:
            os.unlink(path)

    def test_nonexistent_file_raises(self) -> None:
        """Should raise FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            extract_patterns_from_nvd("/nonexistent/file.json")

    def test_invalid_json_raises(self) -> None:
        """Should raise on invalid JSON content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("this is not valid json {{{")
            path = f.name
        try:
            with pytest.raises(json.JSONDecodeError):
                extract_patterns_from_nvd(path)
        finally:
            os.unlink(path)
