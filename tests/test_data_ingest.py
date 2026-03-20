"""Unit tests for NVD CVE data ingestion (vulnpredict.data_ingest)."""

from __future__ import annotations

import json
import os
import tempfile

import pytest
import responses

from vulnpredict.data_ingest import fetch_nvd_cve_data

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            }
        }
    ],
}


# ---------------------------------------------------------------------------
# Successful fetch
# ---------------------------------------------------------------------------


class TestFetchNvdCveDataSuccess:
    """Tests for successful NVD data fetching."""

    @responses.activate
    def test_fetches_and_saves_json(self, tmp_path: object) -> None:
        """Should fetch data from NVD and save valid JSON to the output file."""
        out_file = os.path.join(str(tmp_path), "nvd_2024.json")
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            json=SAMPLE_NVD_RESPONSE,
            status=200,
        )
        fetch_nvd_cve_data(2024, out_file)
        assert os.path.exists(out_file)
        with open(out_file) as f:
            data = json.load(f)
        assert data["totalResults"] == 1
        assert data["vulnerabilities"][0]["cve"]["id"] == "CVE-2024-0001"

    @responses.activate
    def test_constructs_correct_url(self) -> None:
        """Should construct the URL with correct year-based date range."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            responses.add(
                responses.GET,
                NVD_BASE_URL,
                json=SAMPLE_NVD_RESPONSE,
                status=200,
            )
            fetch_nvd_cve_data(2023, out_file)
            assert len(responses.calls) == 1
            url = responses.calls[0].request.url
            assert "2023-01-01" in url
            assert "2023-12-31" in url
        finally:
            os.unlink(out_file)

    @responses.activate
    def test_sends_api_key_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should include apiKey header when NVD_API_KEY is set."""
        monkeypatch.setenv("NVD_API_KEY", "test-key-12345")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            responses.add(
                responses.GET,
                NVD_BASE_URL,
                json=SAMPLE_NVD_RESPONSE,
                status=200,
            )
            fetch_nvd_cve_data(2024, out_file)
            assert responses.calls[0].request.headers.get("apiKey") == "test-key-12345"
        finally:
            os.unlink(out_file)

    @responses.activate
    def test_no_api_key_header_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should not include apiKey header when NVD_API_KEY is not set."""
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            responses.add(
                responses.GET,
                NVD_BASE_URL,
                json=SAMPLE_NVD_RESPONSE,
                status=200,
            )
            fetch_nvd_cve_data(2024, out_file)
            assert "apiKey" not in responses.calls[0].request.headers
        finally:
            os.unlink(out_file)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestFetchNvdCveDataErrors:
    """Tests for error handling in NVD data fetching."""

    @responses.activate
    def test_http_500_raises(self, tmp_path: object) -> None:
        """Should raise on HTTP 500 server error."""
        out_file = os.path.join(str(tmp_path), "nvd.json")
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            json={"error": "Internal Server Error"},
            status=500,
        )
        with pytest.raises(Exception):
            fetch_nvd_cve_data(2024, out_file)
        assert not os.path.exists(out_file)

    @responses.activate
    def test_http_403_raises(self, tmp_path: object) -> None:
        """Should raise on HTTP 403 forbidden."""
        out_file = os.path.join(str(tmp_path), "nvd.json")
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            json={"error": "Forbidden"},
            status=403,
        )
        with pytest.raises(Exception):
            fetch_nvd_cve_data(2024, out_file)

    @responses.activate
    def test_http_429_rate_limit_raises(self, tmp_path: object) -> None:
        """Should raise on HTTP 429 rate limiting."""
        out_file = os.path.join(str(tmp_path), "nvd.json")
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            json={"error": "Rate limit exceeded"},
            status=429,
        )
        with pytest.raises(Exception):
            fetch_nvd_cve_data(2024, out_file)

    @responses.activate
    def test_connection_error_raises(self, tmp_path: object) -> None:
        """Should raise on connection error."""
        out_file = os.path.join(str(tmp_path), "nvd.json")
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            body=ConnectionError("Connection refused"),
        )
        with pytest.raises(Exception):
            fetch_nvd_cve_data(2024, out_file)

    @responses.activate
    def test_invalid_output_path_raises(self) -> None:
        """Should raise OSError when output path is not writable."""
        responses.add(
            responses.GET,
            NVD_BASE_URL,
            json=SAMPLE_NVD_RESPONSE,
            status=200,
        )
        with pytest.raises(OSError):
            fetch_nvd_cve_data(2024, "/nonexistent/dir/nvd.json")
