"""Unit tests for the TypeScript/TSX analyzer."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, List

import pytest

from vulnpredict.ts_analyzer import (
    detect_any_type_abuse,
    detect_non_null_assertion,
    detect_ts_suppression_comments,
    detect_type_assertion_bypass,
    scan_ts_directory,
    scan_ts_file,
)


# ---------------------------------------------------------------------------
# any type abuse tests
# ---------------------------------------------------------------------------


class TestAnyTypeAbuse:
    """Tests for detecting excessive any type usage."""

    def test_any_annotation(self) -> None:
        lines = ["const x: any = 'hello';\n"]
        findings = detect_any_type_abuse(lines, "test.ts")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-TS-001"

    def test_any_generic(self) -> None:
        lines = ["const x = <any>value;\n"]
        findings = detect_any_type_abuse(lines, "test.ts")
        assert len(findings) == 1

    def test_as_any(self) -> None:
        lines = ["const x = value as any;\n"]
        findings = detect_any_type_abuse(lines, "test.ts")
        assert len(findings) == 1

    def test_specific_type_no_match(self) -> None:
        lines = ["const x: string = 'hello';\n"]
        findings = detect_any_type_abuse(lines, "test.ts")
        assert len(findings) == 0

    def test_comment_skipped(self) -> None:
        lines = ["// const x: any = 'hello';\n"]
        findings = detect_any_type_abuse(lines, "test.ts")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["const x: any = 1;\n"]
        findings = detect_any_type_abuse(lines, "app.ts")
        assert findings[0]["cwe"] == "CWE-1007"
        assert findings[0]["severity"] == "low"
        assert findings[0]["file"] == "app.ts"
        assert findings[0]["line"] == 1


# ---------------------------------------------------------------------------
# Type assertion bypass tests
# ---------------------------------------------------------------------------


class TestTypeAssertionBypass:
    """Tests for detecting type assertion bypasses."""

    def test_as_any(self) -> None:
        lines = ["const x = value as any;\n"]
        findings = detect_type_assertion_bypass(lines, "test.ts")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-TS-002"

    def test_as_unknown(self) -> None:
        lines = ["const x = value as unknown;\n"]
        findings = detect_type_assertion_bypass(lines, "test.ts")
        assert len(findings) == 1

    def test_angle_bracket_any(self) -> None:
        lines = ["const x = <any>(value);\n"]
        findings = detect_type_assertion_bypass(lines, "test.ts")
        assert len(findings) == 1

    def test_safe_assertion(self) -> None:
        lines = ["const x = value as string;\n"]
        findings = detect_type_assertion_bypass(lines, "test.ts")
        assert len(findings) == 0

    def test_finding_severity(self) -> None:
        lines = ["const x = value as any;\n"]
        findings = detect_type_assertion_bypass(lines, "test.ts")
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Non-null assertion tests
# ---------------------------------------------------------------------------


class TestNonNullAssertion:
    """Tests for detecting non-null assertion abuse."""

    def test_non_null_assertion(self) -> None:
        lines = ["const x = obj!.property;\n"]
        findings = detect_non_null_assertion(lines, "test.ts")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-TS-003"

    def test_no_assertion(self) -> None:
        lines = ["const x = obj.property;\n"]
        findings = detect_non_null_assertion(lines, "test.ts")
        assert len(findings) == 0

    def test_comment_skipped(self) -> None:
        lines = ["// const x = obj!.property;\n"]
        findings = detect_non_null_assertion(lines, "test.ts")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["const x = obj!.property;\n"]
        findings = detect_non_null_assertion(lines, "test.ts")
        assert findings[0]["cwe"] == "CWE-476"


# ---------------------------------------------------------------------------
# TS suppression comment tests
# ---------------------------------------------------------------------------


class TestTsSuppression:
    """Tests for detecting TypeScript error suppression comments."""

    def test_ts_ignore(self) -> None:
        lines = ["// @ts-ignore\n"]
        findings = detect_ts_suppression_comments(lines, "test.ts")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-TS-004"

    def test_ts_expect_error(self) -> None:
        lines = ["// @ts-expect-error\n"]
        findings = detect_ts_suppression_comments(lines, "test.ts")
        assert len(findings) == 1

    def test_normal_comment(self) -> None:
        lines = ["// This is a normal comment\n"]
        findings = detect_ts_suppression_comments(lines, "test.ts")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# File scanning tests
# ---------------------------------------------------------------------------


class TestFileScan:
    """Tests for file-level TypeScript scanning."""

    def test_scan_ts_file_with_issues(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            const x: any = 'hello';
            const y = value as any;
            const z = obj!.property;
            // @ts-ignore
            const w = eval('code');
        """)
        filepath = tmp_path / "app.ts"
        filepath.write_text(code)
        findings = scan_ts_file(str(filepath))
        rule_ids = {f["rule_id"] for f in findings}
        assert "VP-TS-001" in rule_ids  # any type
        assert "VP-TS-002" in rule_ids  # type assertion bypass
        assert "VP-TS-003" in rule_ids  # non-null assertion
        assert "VP-TS-004" in rule_ids  # ts-ignore

    def test_scan_tsx_file(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            const Component = (props: any) => {
                return <div>{props.data}</div>;
            };
        """)
        filepath = tmp_path / "Component.tsx"
        filepath.write_text(code)
        findings = scan_ts_file(str(filepath))
        assert any(f["rule_id"] == "VP-TS-001" for f in findings)

    def test_scan_clean_ts_file(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            const x: string = 'hello';
            const y: number = 42;
            function add(a: number, b: number): number {
                return a + b;
            }
        """)
        filepath = tmp_path / "clean.ts"
        filepath.write_text(code)
        findings = scan_ts_file(str(filepath))
        assert len(findings) == 0

    def test_scan_empty_file(self, tmp_path: Any) -> None:
        filepath = tmp_path / "empty.ts"
        filepath.write_text("")
        findings = scan_ts_file(str(filepath))
        assert findings == []

    def test_scan_nonexistent_file(self) -> None:
        findings = scan_ts_file("/nonexistent/file.ts")
        assert findings == []

    def test_js_patterns_applied_to_ts(self, tmp_path: Any) -> None:
        """Verify that JS security patterns (prototype pollution etc.) work on .ts files."""
        code = textwrap.dedent("""\
            const obj: Record<string, unknown> = {};
            obj["__proto__"] = malicious;
        """)
        filepath = tmp_path / "vuln.ts"
        filepath.write_text(code)
        findings = scan_ts_file(str(filepath))
        assert any(f["rule_id"] == "VP-JS-001" for f in findings)


# ---------------------------------------------------------------------------
# Directory scanning tests
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    """Tests for directory-level TypeScript scanning."""

    def test_scan_directory(self, tmp_path: Any) -> None:
        (tmp_path / "app.ts").write_text("const x: any = 1;\n")
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "utils.tsx").write_text("const y = value as any;\n")
        findings = scan_ts_directory(str(tmp_path))
        assert len(findings) >= 2

    def test_skip_node_modules(self, tmp_path: Any) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.ts").write_text("const x: any = 1;\n")
        findings = scan_ts_directory(str(tmp_path))
        assert len(findings) == 0

    def test_only_ts_tsx_files(self, tmp_path: Any) -> None:
        (tmp_path / "app.js").write_text("const x = eval('code');\n")
        (tmp_path / "app.ts").write_text("const y: any = 1;\n")
        findings = scan_ts_directory(str(tmp_path))
        # Only .ts file should be scanned
        assert all(f["file"].endswith(".ts") for f in findings)

    def test_empty_directory(self, tmp_path: Any) -> None:
        findings = scan_ts_directory(str(tmp_path))
        assert findings == []
