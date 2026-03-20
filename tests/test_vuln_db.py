"""Tests for the vulnerability database client (vuln_db.py)."""

import json
import os
import tempfile
from unittest import mock

import pytest
import requests

from vulnpredict.vuln_db import (
    VulnCache,
    _parse_severity,
    _parse_vuln,
    _request_with_retry,
    check_package_batch,
    check_package_vulnerabilities,
    check_vulnerable,
)

# ---------------------------------------------------------------------------
# Sample OSV API responses
# ---------------------------------------------------------------------------

SAMPLE_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "SQL injection in example-package",
            "aliases": ["CVE-2024-12345"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"cvss_score": 9.8, "severity": "CRITICAL"},
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"},
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"},
            ],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "example-package"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
    ]
}

SAMPLE_VULN_NO_CVSS = {
    "vulns": [
        {
            "id": "PYSEC-2024-001",
            "summary": "XSS in another-package",
            "aliases": ["CVE-2024-99999"],
            "database_specific": {"severity": "HIGH"},
            "references": [],
            "affected": [],
        }
    ]
}

EMPTY_RESPONSE = {"vulns": []}

BATCH_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "summary": "RCE in pkg-a",
                    "aliases": ["CVE-2024-00001"],
                    "database_specific": {"cvss_score": 9.0},
                    "references": [],
                    "affected": [],
                }
            ]
        },
        {"vulns": []},
    ]
}


def _make_mock_response(json_data, status_code=200, raise_for_status=None):
    """Helper to create a properly configured mock response."""
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    if raise_for_status:
        resp.raise_for_status.side_effect = raise_for_status
    else:
        resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# Tests for VulnCache
# ---------------------------------------------------------------------------


class TestVulnCache:
    """Tests for the JSON file-based vulnerability cache."""

    def test_cache_miss_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = cache.get("PyPI", "nonexistent", "1.0.0")
            assert result is None

    def test_cache_put_and_get(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            vulns = [{"vuln_id": "GHSA-test", "severity": "high"}]
            cache.put("PyPI", "test-pkg", "1.0.0", vulns)
            result = cache.get("PyPI", "test-pkg", "1.0.0")
            assert result == vulns

    def test_cache_expired_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir, ttl=0)
            cache.put("PyPI", "test-pkg", "1.0.0", [{"vuln_id": "test"}])
            # TTL=0 means immediately expired
            import time

            time.sleep(0.01)
            result = cache.get("PyPI", "test-pkg", "1.0.0")
            assert result is None

    def test_cache_clear(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            cache.put("PyPI", "pkg-a", "1.0", [])
            cache.put("PyPI", "pkg-b", "2.0", [])
            count = cache.clear()
            assert count == 2
            assert cache.get("PyPI", "pkg-a", "1.0") is None

    def test_cache_key_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            vulns = [{"vuln_id": "test"}]
            cache.put("PyPI", "Test-Pkg", "1.0.0", vulns)
            result = cache.get("pypi", "test-pkg", "1.0.0")
            assert result == vulns

    def test_cache_handles_corrupted_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            # Write a corrupted file
            key = cache._cache_key("PyPI", "test", "1.0")
            path = cache._path(key)
            with open(path, "w") as f:
                f.write("not valid json{{{")
            result = cache.get("PyPI", "test", "1.0")
            assert result is None

    def test_cache_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = os.path.join(tmpdir, "nested", "cache")
            cache = VulnCache(cache_dir=cache_dir)
            assert os.path.isdir(cache_dir)

    def test_cache_file_permissions(self):
        """Verify cache files are created with owner-only permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            cache.put("PyPI", "test-pkg", "1.0.0", [])
            key = cache._cache_key("PyPI", "test-pkg", "1.0.0")
            path = cache._path(key)
            mode = os.stat(path).st_mode & 0o777
            assert mode == 0o600

    def test_cache_put_handles_oserror(self):
        """Verify cache put handles write errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            # Make the cache directory read-only
            os.chmod(tmpdir, 0o444)
            try:
                # Should not raise, just log
                cache.put("PyPI", "test", "1.0", [])
                result = cache.get("PyPI", "test", "1.0")
                assert result is None
            finally:
                os.chmod(tmpdir, 0o755)


# ---------------------------------------------------------------------------
# Tests for _parse_severity
# ---------------------------------------------------------------------------


class TestParseSeverity:
    """Tests for severity parsing from OSV records."""

    def test_critical_cvss(self):
        vuln = {"database_specific": {"cvss_score": 9.8}}
        label, score = _parse_severity(vuln)
        assert label == "critical"
        assert score == 9.8

    def test_high_cvss(self):
        vuln = {"database_specific": {"cvss_score": 7.5}}
        label, score = _parse_severity(vuln)
        assert label == "high"
        assert score == 7.5

    def test_medium_cvss(self):
        vuln = {"database_specific": {"cvss_score": 5.0}}
        label, score = _parse_severity(vuln)
        assert label == "medium"
        assert score == 5.0

    def test_low_cvss(self):
        vuln = {"database_specific": {"cvss_score": 2.0}}
        label, score = _parse_severity(vuln)
        assert label == "low"
        assert score == 2.0

    def test_severity_from_database_specific(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        label, score = _parse_severity(vuln)
        assert label == "high"
        assert score is None

    def test_moderate_maps_to_medium(self):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        label, score = _parse_severity(vuln)
        assert label == "medium"

    def test_unknown_severity(self):
        vuln = {}
        label, score = _parse_severity(vuln)
        assert label == "unknown"
        assert score is None


# ---------------------------------------------------------------------------
# Tests for _parse_vuln
# ---------------------------------------------------------------------------


class TestParseVuln:
    """Tests for converting OSV records to VulnPredict findings."""

    def test_full_vuln_record(self):
        raw = SAMPLE_VULN_RESPONSE["vulns"][0]
        result = _parse_vuln(raw)
        assert result["vuln_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert "CVE-2024-12345" in result["cve_ids"]
        assert result["severity"] == "critical"
        assert result["cvss_score"] == 9.8
        assert len(result["advisory_urls"]) == 2
        assert len(result["affected_ranges"]) == 1
        assert result["affected_ranges"][0]["introduced"] == "0"
        assert result["affected_ranges"][0]["fixed"] == "2.0.0"

    def test_vuln_without_cvss(self):
        raw = SAMPLE_VULN_NO_CVSS["vulns"][0]
        result = _parse_vuln(raw)
        assert result["vuln_id"] == "PYSEC-2024-001"
        assert result["severity"] == "high"
        assert result["cvss_score"] is None

    def test_vuln_with_no_details(self):
        raw = {"id": "TEST-001"}
        result = _parse_vuln(raw)
        assert result["vuln_id"] == "TEST-001"
        assert result["cve_ids"] == []
        assert result["advisory_urls"] == []
        assert result["affected_ranges"] == []


# ---------------------------------------------------------------------------
# Tests for _request_with_retry
# ---------------------------------------------------------------------------


class TestRequestWithRetry:
    """Tests for the retry/backoff logic."""

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_retries_on_429(self, mock_post, mock_sleep):
        resp_429 = _make_mock_response({}, status_code=429)
        resp_200 = _make_mock_response({"vulns": []}, status_code=200)
        mock_post.side_effect = [resp_429, resp_200]

        result = _request_with_retry("http://test", {}, "test-label")
        assert result == {"vulns": []}
        assert mock_post.call_count == 2
        mock_sleep.assert_called_once()

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_retries_on_500(self, mock_post, mock_sleep):
        resp_500 = _make_mock_response({}, status_code=500)
        resp_200 = _make_mock_response({"vulns": []}, status_code=200)
        mock_post.side_effect = [resp_500, resp_200]

        result = _request_with_retry("http://test", {}, "test-label")
        assert result == {"vulns": []}
        assert mock_post.call_count == 2

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_retries_on_timeout(self, mock_post, mock_sleep):
        mock_post.side_effect = [
            requests.exceptions.Timeout("timeout"),
            _make_mock_response({"vulns": []}, status_code=200),
        ]

        result = _request_with_retry("http://test", {}, "test-label")
        assert result == {"vulns": []}
        assert mock_post.call_count == 2

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_none_after_max_retries(self, mock_post, mock_sleep):
        resp_500 = _make_mock_response({}, status_code=500)
        mock_post.return_value = resp_500

        result = _request_with_retry("http://test", {}, "test-label")
        assert result is None
        assert mock_post.call_count == 3  # MAX_RETRIES

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_exponential_backoff_timing(self, mock_post, mock_sleep):
        resp_429 = _make_mock_response({}, status_code=429)
        mock_post.return_value = resp_429

        _request_with_retry("http://test", {}, "test-label")
        # Should sleep with exponential backoff: 1.0, 2.0, (no sleep after last)
        assert mock_sleep.call_count == 3
        calls = [c.args[0] for c in mock_sleep.call_args_list]
        assert calls[0] == 1.0
        assert calls[1] == 2.0

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_none_on_http_error(self, mock_post):
        resp = _make_mock_response(
            {},
            status_code=403,
            raise_for_status=requests.exceptions.HTTPError("403 Forbidden"),
        )
        mock_post.return_value = resp

        result = _request_with_retry("http://test", {}, "test-label")
        assert result is None
        assert mock_post.call_count == 1  # No retry on 4xx (non-429)

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_none_on_json_decode_error(self, mock_post):
        resp = _make_mock_response({}, status_code=200)
        resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_post.return_value = resp

        result = _request_with_retry("http://test", {}, "test-label")
        assert result is None


# ---------------------------------------------------------------------------
# Tests for check_package_vulnerabilities
# ---------------------------------------------------------------------------


class TestCheckPackageVulnerabilities:
    """Tests for single-package vulnerability lookup."""

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_parsed_vulns(self, mock_post):
        mock_post.return_value = _make_mock_response(SAMPLE_VULN_RESPONSE)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "example-package", "1.0.0", cache=cache)

        assert len(result) == 1
        assert result[0]["vuln_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert "CVE-2024-12345" in result[0]["cve_ids"]

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_empty_for_safe_package(self, mock_post):
        mock_post.return_value = _make_mock_response(EMPTY_RESPONSE)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "safe-package", "1.0.0", cache=cache)

        assert result == []

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_uses_cache_on_second_call(self, mock_post):
        mock_post.return_value = _make_mock_response(SAMPLE_VULN_RESPONSE)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            # First call hits API
            check_package_vulnerabilities("PyPI", "example-package", "1.0.0", cache=cache)
            # Second call should use cache
            result = check_package_vulnerabilities("PyPI", "example-package", "1.0.0", cache=cache)

        assert mock_post.call_count == 1  # Only one API call
        assert len(result) == 1

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_handles_timeout(self, mock_post, mock_sleep):
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "test", "1.0.0", cache=cache)

        assert result == []

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_handles_connection_error(self, mock_post, mock_sleep):
        mock_post.side_effect = requests.exceptions.ConnectionError("No network")

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "test", "1.0.0", cache=cache)

        assert result == []

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_handles_http_error(self, mock_post):
        mock_post.return_value = _make_mock_response(
            {},
            status_code=403,
            raise_for_status=requests.exceptions.HTTPError("403 Forbidden"),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "test", "1.0.0", cache=cache)

        assert result == []

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_handles_json_decode_error(self, mock_post):
        resp = _make_mock_response({}, status_code=200)
        resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_post.return_value = resp

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            result = check_package_vulnerabilities("PyPI", "test", "1.0.0", cache=cache)

        assert result == []


# ---------------------------------------------------------------------------
# Tests for check_package_batch
# ---------------------------------------------------------------------------


class TestCheckPackageBatch:
    """Tests for batch vulnerability lookup."""

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_batch_returns_results(self, mock_post):
        mock_post.return_value = _make_mock_response(BATCH_RESPONSE)

        queries = [
            {"ecosystem": "PyPI", "package": "pkg-a", "version": "1.0"},
            {"ecosystem": "PyPI", "package": "pkg-b", "version": "2.0"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            results = check_package_batch(queries, cache=cache)

        assert "PyPI:pkg-a@1.0" in results
        assert len(results["PyPI:pkg-a@1.0"]) == 1
        assert "PyPI:pkg-b@2.0" in results
        assert len(results["PyPI:pkg-b@2.0"]) == 0

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_batch_uses_cache(self, mock_post):
        mock_post.return_value = _make_mock_response({"results": [{"vulns": []}]})

        queries = [
            {"ecosystem": "PyPI", "package": "cached-pkg", "version": "1.0"},
            {"ecosystem": "PyPI", "package": "uncached-pkg", "version": "2.0"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            # Pre-populate cache for one package
            cache.put("PyPI", "cached-pkg", "1.0", [{"vuln_id": "cached-vuln"}])
            results = check_package_batch(queries, cache=cache)

        assert results["PyPI:cached-pkg@1.0"] == [{"vuln_id": "cached-vuln"}]
        # Only the uncached package should trigger an API call
        assert mock_post.call_count == 1

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_batch_all_cached(self, mock_post):
        queries = [
            {"ecosystem": "PyPI", "package": "a", "version": "1.0"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            cache.put("PyPI", "a", "1.0", [])
            results = check_package_batch(queries, cache=cache)

        assert mock_post.call_count == 0
        assert results["PyPI:a@1.0"] == []

    @mock.patch("vulnpredict.vuln_db.time.sleep")
    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_batch_falls_back_on_failure(self, mock_post, mock_sleep):
        """When batch API fails, individual queries should be attempted."""
        # First 3 calls (batch retries) return 500, then individual calls succeed
        resp_500 = _make_mock_response({}, status_code=500)
        resp_ok = _make_mock_response(EMPTY_RESPONSE)
        mock_post.side_effect = [resp_500, resp_500, resp_500, resp_ok]

        queries = [
            {"ecosystem": "PyPI", "package": "pkg-a", "version": "1.0"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            results = check_package_batch(queries, cache=cache)

        assert "PyPI:pkg-a@1.0" in results


# ---------------------------------------------------------------------------
# Tests for check_vulnerable (drop-in replacement)
# ---------------------------------------------------------------------------


class TestCheckVulnerable:
    """Tests for the drop-in replacement for check_vulnerable_stub."""

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_true_when_vulnerable(self, mock_post):
        mock_post.return_value = _make_mock_response(SAMPLE_VULN_RESPONSE)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            with mock.patch("vulnpredict.vuln_db.VulnCache", return_value=cache):
                is_vuln, details = check_vulnerable("example-package", "1.0.0")

        assert is_vuln is True
        assert details is not None
        assert details["type"] == "vulnerable_dependency"
        assert details["vuln_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert details["package"] == "example-package"
        assert details["total_vulnerabilities"] == 1

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_false_when_safe(self, mock_post):
        mock_post.return_value = _make_mock_response(EMPTY_RESPONSE)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            with mock.patch("vulnpredict.vuln_db.VulnCache", return_value=cache):
                is_vuln, details = check_vulnerable("safe-package", "1.0.0")

        assert is_vuln is False
        assert details is None

    @mock.patch("vulnpredict.vuln_db.requests.post")
    def test_returns_most_severe_vuln(self, mock_post):
        multi_vuln_response = {
            "vulns": [
                {
                    "id": "LOW-001",
                    "summary": "Low severity issue",
                    "aliases": [],
                    "database_specific": {"cvss_score": 2.0},
                    "references": [],
                    "affected": [],
                },
                {
                    "id": "CRIT-001",
                    "summary": "Critical RCE",
                    "aliases": ["CVE-2024-99999"],
                    "database_specific": {"cvss_score": 9.9},
                    "references": [],
                    "affected": [],
                },
            ]
        }
        mock_post.return_value = _make_mock_response(multi_vuln_response)

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = VulnCache(cache_dir=tmpdir)
            with mock.patch("vulnpredict.vuln_db.VulnCache", return_value=cache):
                is_vuln, details = check_vulnerable("multi-vuln-pkg", "1.0.0")

        assert is_vuln is True
        assert details["vuln_id"] == "CRIT-001"
        assert details["severity"] == "critical"
        assert details["total_vulnerabilities"] == 2
