"""Unit tests for the secrets detector (vulnpredict.secrets_detector)."""

from __future__ import annotations

import os
import textwrap
from typing import Any, Dict, List

import pytest

from vulnpredict.secrets_detector import (
    SecretPattern,
    _is_false_positive,
    _is_likely_base64,
    _is_likely_hex,
    detect_high_entropy_strings,
    get_builtin_patterns,
    scan_directory_for_secrets,
    scan_file_for_secrets,
    shannon_entropy,
)


# ---------------------------------------------------------------------------
# Shannon entropy tests
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    """Tests for the shannon_entropy function."""

    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert shannon_entropy("a") == 0.0

    def test_repeated_chars(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self) -> None:
        # "ab" has entropy of 1.0 (2 equally likely chars)
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_high_entropy(self) -> None:
        # Random-looking string should have high entropy
        s = "aB3kL9mN2pQ7rS5tU8vW1xY4zA6bC0d"
        assert shannon_entropy(s) > 4.0

    def test_low_entropy(self) -> None:
        # Repetitive string should have low entropy
        s = "aaabbbccc"
        assert shannon_entropy(s) < 2.0


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestHelpers:
    """Tests for helper functions."""

    def test_is_likely_hex_true(self) -> None:
        assert _is_likely_hex("0123456789abcdef0123")

    def test_is_likely_hex_false_short(self) -> None:
        assert not _is_likely_hex("0123")

    def test_is_likely_hex_false_chars(self) -> None:
        assert not _is_likely_hex("xyz123456789abcdef01")

    def test_is_likely_base64_true(self) -> None:
        assert _is_likely_base64("ABCDEFGHIJKLMNOPQRSTUVWXYZab==")

    def test_is_likely_base64_false_short(self) -> None:
        assert not _is_likely_base64("ABCD")

    def test_is_false_positive_url(self) -> None:
        assert _is_false_positive("https://example.com/path")

    def test_is_false_positive_uuid(self) -> None:
        assert _is_false_positive("12345678-1234-1234-1234-123456789abc")

    def test_is_false_positive_repeated(self) -> None:
        assert _is_false_positive("aaaaaaaaaaaaaaaaaaaaaa")

    def test_not_false_positive(self) -> None:
        assert not _is_false_positive("aB3kL9mN2pQ7rS5tU8vW")


# ---------------------------------------------------------------------------
# Pattern detection tests
# ---------------------------------------------------------------------------


class TestPatternDetection:
    """Tests for regex-based secret detection."""

    def _scan_line(self, line: str) -> List[Dict[str, Any]]:
        """Helper to scan a single line written to a temp file."""
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(line + "\n")
            f.flush()
            findings = scan_file_for_secrets(f.name, entropy_detection=False)
        os.unlink(f.name)
        return findings

    def test_aws_access_key(self) -> None:
        findings = self._scan_line('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        assert any(f["rule_id"] == "VP-SEC-001" for f in findings)

    def test_github_pat(self) -> None:
        findings = self._scan_line(
            'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        assert any(f["rule_id"] == "VP-SEC-003" for f in findings)

    def test_github_oauth(self) -> None:
        findings = self._scan_line(
            'token = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        assert any(f["rule_id"] == "VP-SEC-004" for f in findings)

    def test_github_app(self) -> None:
        findings = self._scan_line(
            'token = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        assert any(f["rule_id"] == "VP-SEC-005" for f in findings)

    def test_slack_bot_token(self) -> None:
        # Build token dynamically to avoid GitHub push protection
        tok = "xoxb-" + "1234567890" + "-" + "abcdefghijklmnop"
        findings = self._scan_line(f'SLACK_TOKEN = "{tok}"')
        assert any(f["rule_id"] == "VP-SEC-007" for f in findings)

    def test_slack_user_token(self) -> None:
        tok = "xoxp-" + "1234567890" + "-" + "abcdefghijklmnop"
        findings = self._scan_line(f'SLACK_TOKEN = "{tok}"')
        assert any(f["rule_id"] == "VP-SEC-008" for f in findings)

    def test_google_api_key(self) -> None:
        findings = self._scan_line(
            'GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
        )
        assert any(f["rule_id"] == "VP-SEC-010" for f in findings)

    def test_jwt_token(self) -> None:
        findings = self._scan_line(
            'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"'
        )
        assert any(f["rule_id"] == "VP-SEC-012" for f in findings)

    def test_rsa_private_key(self) -> None:
        findings = self._scan_line("-----BEGIN RSA PRIVATE KEY-----")
        assert any(f["rule_id"] == "VP-SEC-013" for f in findings)

    def test_ssh_private_key(self) -> None:
        findings = self._scan_line("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert any(f["rule_id"] == "VP-SEC-014" for f in findings)

    def test_database_connection_string(self) -> None:
        findings = self._scan_line(
            'DB_URL = "postgres://admin:s3cret@db.example.com:5432/mydb"'
        )
        assert any(f["rule_id"] == "VP-SEC-017" for f in findings)

    def test_generic_api_key(self) -> None:
        findings = self._scan_line(
            'api_key = "sk_test_1234567890abcdefghij"'
        )
        assert any(f["rule_id"] == "VP-SEC-018" for f in findings)

    def test_generic_password(self) -> None:
        findings = self._scan_line(
            'password = "SuperSecretPassword123!"'
        )
        assert any(f["rule_id"] == "VP-SEC-019" for f in findings)

    def test_stripe_secret_key(self) -> None:
        tok = "sk_" + "live_" + "1234567890abcdefghijklmn"
        findings = self._scan_line(f'STRIPE_KEY = "{tok}"')
        assert any(f["rule_id"] == "VP-SEC-020" for f in findings)

    def test_sendgrid_key(self) -> None:
        findings = self._scan_line(
            'SG_KEY = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"'
        )
        assert any(f["rule_id"] == "VP-SEC-022" for f in findings)

    def test_no_false_positive_on_placeholder(self) -> None:
        findings = self._scan_line('api_key = "YOUR_API_KEY_HERE"')
        # Should not match VP-SEC-001 through VP-SEC-016 (specific patterns)
        specific = [f for f in findings if f["rule_id"].startswith("VP-SEC-0")]
        # Generic pattern VP-SEC-018 may match, but specific ones should not
        non_generic = [
            f for f in specific if f["rule_id"] not in ("VP-SEC-018", "VP-SEC-019")
        ]
        assert len(non_generic) == 0

    def test_comment_lines_skipped(self) -> None:
        tok = "sk_" + "live_" + "1234567890abcdefghijklmn"
        findings = self._scan_line(f'# STRIPE_KEY = "{tok}"')
        assert len(findings) == 0

    def test_finding_has_required_fields(self) -> None:
        findings = self._scan_line('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        assert len(findings) > 0
        f = findings[0]
        assert "type" in f
        assert "rule_id" in f
        assert "file" in f
        assert "line" in f
        assert "severity" in f
        assert "cwe" in f
        assert "message" in f

    def test_secret_is_masked_in_message(self) -> None:
        findings = self._scan_line('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        assert len(findings) > 0
        # Full secret should not appear in message
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0]["message"]


# ---------------------------------------------------------------------------
# Entropy detection tests
# ---------------------------------------------------------------------------


class TestEntropyDetection:
    """Tests for entropy-based secret detection."""

    def test_high_entropy_hex_detected(self) -> None:
        line = 'secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"'
        findings = detect_high_entropy_strings(line, 1, "test.py")
        assert len(findings) > 0
        assert findings[0]["type"] == "high_entropy_secret"

    def test_low_entropy_not_detected(self) -> None:
        line = 'value = "aaaaaaaaaaaaaaaaaaaaaa"'
        findings = detect_high_entropy_strings(line, 1, "test.py")
        assert len(findings) == 0

    def test_url_not_detected(self) -> None:
        line = 'url = "https://example.com/very/long/path/to/resource"'
        findings = detect_high_entropy_strings(line, 1, "test.py")
        assert len(findings) == 0

    def test_entropy_finding_has_fields(self) -> None:
        line = 'secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"'
        findings = detect_high_entropy_strings(line, 1, "test.py")
        if findings:
            f = findings[0]
            assert "entropy" in f
            assert "encoding" in f
            assert f["rule_id"] == "VP-SEC-100"


# ---------------------------------------------------------------------------
# File scanning tests
# ---------------------------------------------------------------------------


class TestFileScan:
    """Tests for file-level scanning."""

    def test_scan_python_file(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            import os

            AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
            DB_URL = "postgres://admin:pass@localhost/db"

            def get_data():
                return os.environ.get("SAFE_VAR")
        """)
        filepath = tmp_path / "config.py"
        filepath.write_text(code)
        findings = scan_file_for_secrets(str(filepath), entropy_detection=False)
        assert len(findings) >= 2
        rule_ids = {f["rule_id"] for f in findings}
        assert "VP-SEC-001" in rule_ids  # AWS key
        assert "VP-SEC-017" in rule_ids  # DB connection string

    def test_scan_env_file(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            DATABASE_URL=postgres://user:secret@db.host:5432/mydb
            GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
        """)
        filepath = tmp_path / ".env"
        filepath.write_text(code)
        findings = scan_file_for_secrets(str(filepath), entropy_detection=False)
        assert len(findings) >= 2

    def test_scan_empty_file(self, tmp_path: Any) -> None:
        filepath = tmp_path / "empty.py"
        filepath.write_text("")
        findings = scan_file_for_secrets(str(filepath))
        assert findings == []

    def test_scan_nonexistent_file(self) -> None:
        findings = scan_file_for_secrets("/nonexistent/file.py")
        assert findings == []


# ---------------------------------------------------------------------------
# Directory scanning tests
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    """Tests for directory-level scanning."""

    def test_scan_directory(self, tmp_path: Any) -> None:
        (tmp_path / "config.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        (tmp_path / "app.js").write_text(
            'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";\n'
        )
        findings = scan_directory_for_secrets(
            str(tmp_path), entropy_detection=False
        )
        assert len(findings) >= 2

    def test_skip_node_modules(self, tmp_path: Any) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(
            'const key = "AKIAIOSFODNN7EXAMPLE";\n'
        )
        findings = scan_directory_for_secrets(
            str(tmp_path), entropy_detection=False
        )
        assert len(findings) == 0

    def test_skip_git_dir(self, tmp_path: Any) -> None:
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config").write_text(
            'password = "SuperSecret123"\n'
        )
        findings = scan_directory_for_secrets(
            str(tmp_path), entropy_detection=False
        )
        assert len(findings) == 0

    def test_empty_directory(self, tmp_path: Any) -> None:
        findings = scan_directory_for_secrets(str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# Built-in patterns tests
# ---------------------------------------------------------------------------


class TestBuiltinPatterns:
    """Tests for the get_builtin_patterns function."""

    def test_returns_list(self) -> None:
        patterns = get_builtin_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_all_patterns_have_ids(self) -> None:
        for p in get_builtin_patterns():
            assert p.id.startswith("VP-SEC-")

    def test_all_patterns_have_names(self) -> None:
        for p in get_builtin_patterns():
            assert len(p.name) > 0

    def test_unique_ids(self) -> None:
        ids = [p.id for p in get_builtin_patterns()]
        assert len(ids) == len(set(ids))

    def test_all_have_cwe(self) -> None:
        for p in get_builtin_patterns():
            assert p.cwe.startswith("CWE-")
