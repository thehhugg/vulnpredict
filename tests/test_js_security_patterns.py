"""Unit tests for JavaScript security pattern detection."""

from __future__ import annotations

import os
import textwrap
from typing import Any, Dict, List

import pytest

from vulnpredict.js_security_patterns import (
    detect_insecure_postmessage,
    detect_insecure_randomness,
    detect_nosql_injection,
    detect_open_redirect,
    detect_prototype_pollution,
    detect_redos,
    scan_js_directory_patterns,
    scan_js_file_patterns,
)


# ---------------------------------------------------------------------------
# Prototype pollution tests
# ---------------------------------------------------------------------------


class TestPrototypePollution:
    """Tests for prototype pollution detection."""

    def test_proto_bracket_assignment(self) -> None:
        lines = ['obj["__proto__"] = malicious;\n']
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-001"

    def test_proto_dot_assignment(self) -> None:
        lines = ["obj.__proto__ = payload;\n"]
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 1

    def test_constructor_prototype(self) -> None:
        lines = ["obj.constructor.prototype = evil;\n"]
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 1

    def test_object_assign_prototype(self) -> None:
        lines = ["Object.assign(target.prototype, source);\n"]
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 1

    def test_safe_code_no_match(self) -> None:
        lines = ["const x = obj.name;\n"]
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 0

    def test_comment_skipped(self) -> None:
        lines = ['// obj["__proto__"] = malicious;\n']
        findings = detect_prototype_pollution(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ['obj["__proto__"] = x;\n']
        findings = detect_prototype_pollution(lines, "test.js")
        assert findings[0]["cwe"] == "CWE-1321"
        assert findings[0]["severity"] == "high"
        assert findings[0]["file"] == "test.js"
        assert findings[0]["line"] == 1


# ---------------------------------------------------------------------------
# ReDoS tests
# ---------------------------------------------------------------------------


class TestReDoS:
    """Tests for ReDoS detection."""

    def test_nested_quantifier_in_regex_literal(self) -> None:
        lines = ["const re = /(a+)+$/;\n"]
        findings = detect_redos(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-002"

    def test_safe_regex(self) -> None:
        lines = ["const re = /^[a-z]+$/;\n"]
        findings = detect_redos(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["const re = /(a+)+$/;\n"]
        findings = detect_redos(lines, "test.js")
        if findings:
            assert findings[0]["cwe"] == "CWE-1333"
            assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Open redirect tests
# ---------------------------------------------------------------------------


class TestOpenRedirect:
    """Tests for open redirect detection."""

    def test_window_location_req(self) -> None:
        lines = ["window.location = req.query.url;\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-003"

    def test_window_location_href_req(self) -> None:
        lines = ["window.location.href = req.body.redirect;\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1

    def test_res_redirect_req(self) -> None:
        lines = ["res.redirect(req.query.next);\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1

    def test_location_replace(self) -> None:
        lines = ["location.replace(query.returnUrl);\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1

    def test_window_location_document_url(self) -> None:
        lines = ["window.location = document.URL;\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1

    def test_res_redirect_variable(self) -> None:
        lines = ["res.redirect(redirect_url);\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 1

    def test_safe_redirect(self) -> None:
        lines = ['res.redirect("/dashboard");\n']
        findings = detect_open_redirect(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["window.location = req.query.url;\n"]
        findings = detect_open_redirect(lines, "test.js")
        assert findings[0]["cwe"] == "CWE-601"
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Insecure randomness tests
# ---------------------------------------------------------------------------


class TestInsecureRandomness:
    """Tests for insecure randomness detection."""

    def test_token_with_math_random(self) -> None:
        lines = ["const token = Math.random().toString(36);\n"]
        findings = detect_insecure_randomness(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-004"

    def test_secret_with_math_random(self) -> None:
        lines = ["const secret = 'prefix' + Math.random().toString(36);\n"]
        findings = detect_insecure_randomness(lines, "test.js")
        assert len(findings) == 1

    def test_safe_random(self) -> None:
        lines = ["const x = Math.random() * 100;\n"]
        findings = detect_insecure_randomness(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["const token = Math.random().toString(36);\n"]
        findings = detect_insecure_randomness(lines, "test.js")
        assert findings[0]["cwe"] == "CWE-330"


# ---------------------------------------------------------------------------
# NoSQL injection tests
# ---------------------------------------------------------------------------


class TestNoSQLInjection:
    """Tests for NoSQL injection detection."""

    def test_find_with_req_body(self) -> None:
        lines = ["db.users.find({ username: req.body.username });\n"]
        findings = detect_nosql_injection(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-005"

    def test_findone_with_req_query(self) -> None:
        lines = ["User.findOne({ email: req.query.email });\n"]
        findings = detect_nosql_injection(lines, "test.js")
        assert len(findings) == 1

    def test_where_operator(self) -> None:
        lines = ["db.users.find({ $where: 'this.name == user' });\n"]
        findings = detect_nosql_injection(lines, "test.js")
        assert len(findings) == 1

    def test_safe_query(self) -> None:
        lines = ['db.users.find({ role: "admin" });\n']
        findings = detect_nosql_injection(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = ["db.users.find({ username: req.body.username });\n"]
        findings = detect_nosql_injection(lines, "test.js")
        assert findings[0]["cwe"] == "CWE-943"
        assert findings[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Insecure postMessage tests
# ---------------------------------------------------------------------------


class TestInsecurePostMessage:
    """Tests for insecure postMessage handler detection."""

    def test_no_origin_check(self) -> None:
        lines = [
            "window.addEventListener('message', function(event) {\n",
            "  processData(event.data);\n",
            "});\n",
        ]
        findings = detect_insecure_postmessage(lines, "test.js")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "VP-JS-006"

    def test_with_origin_check(self) -> None:
        lines = [
            "window.addEventListener('message', function(event) {\n",
            '  if (event.origin !== "https://trusted.com") return;\n',
            "  processData(event.data);\n",
            "});\n",
        ]
        findings = detect_insecure_postmessage(lines, "test.js")
        assert len(findings) == 0

    def test_no_message_listener(self) -> None:
        lines = [
            "window.addEventListener('click', function(event) {\n",
            "  handleClick(event);\n",
            "});\n",
        ]
        findings = detect_insecure_postmessage(lines, "test.js")
        assert len(findings) == 0

    def test_finding_fields(self) -> None:
        lines = [
            "window.addEventListener('message', function(e) {\n",
            "  doStuff(e.data);\n",
            "});\n",
        ]
        findings = detect_insecure_postmessage(lines, "test.js")
        assert findings[0]["cwe"] == "CWE-346"
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# File scanning tests
# ---------------------------------------------------------------------------


class TestFileScan:
    """Tests for file-level JS security scanning."""

    def test_scan_file_with_multiple_issues(self, tmp_path: Any) -> None:
        code = textwrap.dedent("""\
            const obj = {};
            obj["__proto__"] = malicious;

            window.location = req.query.url;

            db.users.find({ username: req.body.username });

            window.addEventListener('message', function(event) {
              processData(event.data);
            });
        """)
        filepath = tmp_path / "app.js"
        filepath.write_text(code)
        findings = scan_js_file_patterns(str(filepath))
        rule_ids = {f["rule_id"] for f in findings}
        assert "VP-JS-001" in rule_ids  # prototype pollution
        assert "VP-JS-003" in rule_ids  # open redirect
        assert "VP-JS-005" in rule_ids  # nosql injection
        assert "VP-JS-006" in rule_ids  # insecure postmessage

    def test_scan_empty_file(self, tmp_path: Any) -> None:
        filepath = tmp_path / "empty.js"
        filepath.write_text("")
        findings = scan_js_file_patterns(str(filepath))
        assert findings == []

    def test_scan_nonexistent_file(self) -> None:
        findings = scan_js_file_patterns("/nonexistent/file.js")
        assert findings == []


# ---------------------------------------------------------------------------
# Directory scanning tests
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    """Tests for directory-level JS security scanning."""

    def test_scan_directory(self, tmp_path: Any) -> None:
        (tmp_path / "app.js").write_text(
            'obj["__proto__"] = x;\n'
        )
        sub = tmp_path / "lib"
        sub.mkdir()
        (sub / "utils.js").write_text(
            "window.location = req.query.url;\n"
        )
        findings = scan_js_directory_patterns(str(tmp_path))
        assert len(findings) >= 2

    def test_skip_node_modules(self, tmp_path: Any) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(
            'obj["__proto__"] = x;\n'
        )
        findings = scan_js_directory_patterns(str(tmp_path))
        assert len(findings) == 0

    def test_empty_directory(self, tmp_path: Any) -> None:
        findings = scan_js_directory_patterns(str(tmp_path))
        assert findings == []
