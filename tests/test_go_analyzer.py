"""Unit tests for the Go security analyzer."""

from __future__ import annotations

import os
import textwrap
from typing import Any

import pytest

from vulnpredict.go_analyzer import scan_go_directory, scan_go_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# Individual rule tests
# ---------------------------------------------------------------------------


class TestSQLInjection:
    """VP-GO-001: SQL injection via string concatenation."""

    def test_string_concat(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "database/sql"
            func f(db *sql.DB, name string) {
                query := "SELECT * FROM users WHERE name = '" + name + "'"
                db.Query(query)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-001" for r in findings)

    def test_fmt_sprintf(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import ("database/sql"; "fmt")
            func f(db *sql.DB, id string) {
                query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
                db.Query(query)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-001" for r in findings)

    def test_parameterized_query_safe(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "database/sql"
            func f(db *sql.DB, name string) {
                db.QueryRow("SELECT * FROM users WHERE name = ?", name)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert not any(r["rule_id"] == "VP-GO-001" for r in findings)


class TestCommandInjection:
    """VP-GO-002/003: Command injection."""

    def test_dynamic_command(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "os/exec"
            func f(input string) {
                exec.Command(input)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-002" for r in findings)

    def test_shell_execution(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "os/exec"
            func f(cmd string) {
                exec.Command("bash", "-c", cmd)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-003" for r in findings)


class TestPathTraversal:
    """VP-GO-004: Path traversal."""

    def test_filepath_join_with_request(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import ("net/http"; "path/filepath")
            func f(w http.ResponseWriter, r *http.Request) {
                path := filepath.Join("/data", r.URL.Path)
                http.ServeFile(w, r, path)
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-004" for r in findings)


class TestWeakCrypto:
    """VP-GO-005/006/007/008: Weak cryptography."""

    def test_des_import(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/des"\nfunc f() { des.NewCipher(nil) }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-005" for r in findings)

    def test_rc4_import(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/rc4"\nfunc f() { rc4.NewCipher(nil) }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-006" for r in findings)

    def test_md5_usage(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/md5"\nfunc f() { md5.New() }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-007" for r in findings)

    def test_sha1_usage(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/sha1"\nfunc f() { sha1.New() }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-008" for r in findings)

    def test_aes_safe(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/aes"\nfunc f() { aes.NewCipher(nil) }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        crypto_rules = {"VP-GO-005", "VP-GO-006", "VP-GO-007", "VP-GO-008"}
        assert not any(r["rule_id"] in crypto_rules for r in findings)


class TestHardcodedCredentials:
    """VP-GO-009: Hardcoded credentials."""

    def test_hardcoded_password(self, tmp_path: Any) -> None:
        code = 'package main\nvar password = "SuperSecretPassword123!"\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-009" for r in findings)

    def test_env_password_safe(self, tmp_path: Any) -> None:
        code = 'package main\nimport "os"\nfunc f() string { return os.Getenv("PASSWORD") }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert not any(r["rule_id"] == "VP-GO-009" for r in findings)


class TestInsecureTLS:
    """VP-GO-010/011: Insecure TLS configuration."""

    def test_skip_verify(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "crypto/tls"
            func f() {
                cfg := &tls.Config{InsecureSkipVerify: true}
                _ = cfg
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-010" for r in findings)

    def test_proper_tls_safe(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "crypto/tls"
            func f() {
                cfg := &tls.Config{MinVersion: tls.VersionTLS13}
                _ = cfg
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert not any(r["rule_id"] == "VP-GO-010" for r in findings)


class TestUnsafePointer:
    """VP-GO-013: Unsafe pointer usage."""

    def test_unsafe_import(self, tmp_path: Any) -> None:
        code = 'package main\nimport "unsafe"\nfunc f() { _ = unsafe.Sizeof(0) }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-013" for r in findings)


class TestIgnoredError:
    """VP-GO-014: Ignored error return."""

    def test_ignored_http_error(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "net/http"
            func f() {
                resp, _ := http.Get("https://example.com")
                _ = resp
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-014" for r in findings)


class TestHTTPWithoutTimeout:
    """VP-GO-015: HTTP client without timeout."""

    def test_default_http_get(self, tmp_path: Any) -> None:
        code = textwrap.dedent('''\
            package main
            import "net/http"
            func f() {
                http.Get("https://example.com")
            }
        ''')
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert any(r["rule_id"] == "VP-GO-015" for r in findings)


# ---------------------------------------------------------------------------
# Fixture file tests
# ---------------------------------------------------------------------------


class TestFixtureFiles:
    """Tests using the Go fixture files."""

    def test_vulnerable_go_has_findings(self) -> None:
        vuln_file = os.path.join(FIXTURES, "vulnerable.go")
        if not os.path.exists(vuln_file):
            pytest.skip("vulnerable.go fixture not found")
        findings = scan_go_file(vuln_file)
        assert len(findings) >= 10
        rule_ids = {f["rule_id"] for f in findings}
        # Should detect at least these categories
        assert "VP-GO-001" in rule_ids  # SQL injection
        assert "VP-GO-005" in rule_ids  # DES
        assert "VP-GO-009" in rule_ids  # Hardcoded creds
        assert "VP-GO-010" in rule_ids  # Insecure TLS

    def test_secure_go_minimal_findings(self) -> None:
        secure_file = os.path.join(FIXTURES, "secure.go")
        if not os.path.exists(secure_file):
            pytest.skip("secure.go fixture not found")
        findings = scan_go_file(secure_file)
        # Secure file should have no critical/high findings
        high_crit = [f for f in findings if f["severity"] in ("critical", "high")]
        assert len(high_crit) == 0


# ---------------------------------------------------------------------------
# Directory scanning tests
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    """Tests for directory-level Go scanning."""

    def test_scan_directory(self, tmp_path: Any) -> None:
        (tmp_path / "main.go").write_text(
            'package main\nimport "crypto/des"\nfunc f() { des.NewCipher(nil) }\n'
        )
        sub = tmp_path / "pkg"
        sub.mkdir()
        (sub / "util.go").write_text(
            'package pkg\nimport "crypto/rc4"\nfunc f() { rc4.NewCipher(nil) }\n'
        )
        findings = scan_go_directory(str(tmp_path))
        rule_ids = {f["rule_id"] for f in findings}
        assert "VP-GO-005" in rule_ids
        assert "VP-GO-006" in rule_ids

    def test_skip_test_files(self, tmp_path: Any) -> None:
        (tmp_path / "main_test.go").write_text(
            'package main\nimport "crypto/des"\nfunc f() { des.NewCipher(nil) }\n'
        )
        findings = scan_go_directory(str(tmp_path))
        assert len(findings) == 0

    def test_skip_vendor_dir(self, tmp_path: Any) -> None:
        vendor = tmp_path / "vendor" / "lib"
        vendor.mkdir(parents=True)
        (vendor / "lib.go").write_text(
            'package lib\nimport "crypto/des"\nfunc f() { des.NewCipher(nil) }\n'
        )
        findings = scan_go_directory(str(tmp_path))
        assert len(findings) == 0

    def test_empty_directory(self, tmp_path: Any) -> None:
        findings = scan_go_directory(str(tmp_path))
        assert findings == []

    def test_nonexistent_file(self) -> None:
        findings = scan_go_file("/nonexistent.go")
        assert findings == []


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------


class TestFindingStructure:
    """Tests for finding dict structure."""

    def test_finding_has_required_fields(self, tmp_path: Any) -> None:
        code = 'package main\nimport "crypto/des"\nfunc f() { des.NewCipher(nil) }\n'
        f = tmp_path / "main.go"
        f.write_text(code)
        findings = scan_go_file(str(f))
        assert len(findings) >= 1
        finding = findings[0]
        assert "type" in finding
        assert "rule_id" in finding
        assert "file" in finding
        assert "line" in finding
        assert "severity" in finding
        assert "cwe" in finding
        assert "message" in finding
        assert finding["type"] == "go_vulnerability"
        assert finding["line"] >= 1
