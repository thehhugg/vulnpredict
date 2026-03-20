"""Unit tests for vulnpredict/formatters/sarif.py.

Tests cover:
- SARIF v2.1.0 schema structure and required fields
- Tool metadata (name, version, informationUri)
- Rule definitions and mapping from finding types
- Result generation for all finding types
- Level mapping (error/warning/note)
- Location and region information
- Code snippet extraction
- Fingerprint generation for deduplication
- write_sarif file output
- SARIF schema validation (if jsonschema is available)
"""

import json
import os
import tempfile

import pytest

from vulnpredict.formatters.sarif import (
    RULES,
    SARIF_SCHEMA,
    SARIF_VERSION,
    _finding_to_result,
    _get_code_snippet,
    _get_level,
    _get_message,
    _get_rule_id,
    format_sarif,
    write_sarif,
)


# =========================================================================
# Sample findings for testing
# =========================================================================
TAINT_FINDING = {
    "type": "taint_analysis",
    "source": [(2, "input")],
    "sink": "eval",
    "sink_line": 5,
    "variable": "user_data",
    "trace": [(2, "input"), (5, "eval")],
    "file": "app.py",
}

INTERPROC_FINDING = {
    "type": "interprocedural_taint",
    "source_func": "get_input",
    "sink_func": "process",
    "sink": "exec",
    "sink_line": 10,
    "tainted_var": "cmd",
    "call_chain": ["get_input", "process"],
    "var_trace": [{"cmd"}],
    "file": "handler.py",
}

DANGEROUS_FUNC_FINDING = {
    "type": "dangerous_function",
    "function": "eval",
    "line": 15,
    "file": "utils.py",
}

SECRET_FINDING = {
    "type": "hardcoded_secret",
    "variable": "API_KEY",
    "line": 3,
    "file": "config.py",
}

COMPLEXITY_FINDING = {
    "type": "high_complexity",
    "complexity": 25,
    "line": 1,
    "file": "complex.py",
}

JS_FINDING = {
    "type": "dangerous_js_function",
    "function": "eval",
    "line": 8,
    "file": "script.js",
}

SCORED_FINDING = {
    "type": "taint_analysis",
    "source": [(1, "input")],
    "sink": "eval",
    "sink_line": 3,
    "variable": "x",
    "trace": [(1, "input"), (3, "eval")],
    "vuln_score": 0.92,
    "file": "test.py",
}


# =========================================================================
# Test: SARIF top-level structure
# =========================================================================
class TestSarifStructure:
    """Verify the top-level SARIF structure."""

    def test_has_schema_field(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        assert result["$schema"] == SARIF_SCHEMA

    def test_has_version(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        assert result["version"] == SARIF_VERSION

    def test_has_runs_array(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        assert "runs" in result
        assert isinstance(result["runs"], list)
        assert len(result["runs"]) == 1

    def test_run_has_tool(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        run = result["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]

    def test_run_has_results(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        run = result["runs"][0]
        assert "results" in run
        assert isinstance(run["results"], list)

    def test_run_has_column_kind(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        run = result["runs"][0]
        assert run["columnKind"] == "utf16CodeUnits"


# =========================================================================
# Test: Tool metadata
# =========================================================================
class TestToolMetadata:
    """Verify tool driver metadata."""

    def test_tool_name(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        driver = result["runs"][0]["tool"]["driver"]
        assert driver["name"] == "VulnPredict"

    def test_tool_has_version(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        driver = result["runs"][0]["tool"]["driver"]
        assert "version" in driver

    def test_tool_has_information_uri(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        driver = result["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver

    def test_rules_only_include_used(self):
        result = json.loads(format_sarif([TAINT_FINDING], "/tmp/test"))
        driver = result["runs"][0]["tool"]["driver"]
        rule_ids = [r["id"] for r in driver["rules"]]
        assert "VP001" in rule_ids
        assert "VP005" not in rule_ids  # Not used

    def test_empty_findings_no_rules(self):
        result = json.loads(format_sarif([], "/tmp/test"))
        driver = result["runs"][0]["tool"]["driver"]
        assert driver["rules"] == []


# =========================================================================
# Test: Rule ID mapping
# =========================================================================
class TestRuleIdMapping:
    """Verify finding types map to correct rule IDs."""

    def test_taint_maps_to_vp001(self):
        assert _get_rule_id({"type": "taint_analysis"}) == "VP001"

    def test_interprocedural_maps_to_vp002(self):
        assert _get_rule_id({"type": "interprocedural_taint"}) == "VP002"

    def test_dangerous_function_maps_to_vp003(self):
        assert _get_rule_id({"type": "dangerous_function"}) == "VP003"

    def test_hardcoded_secret_maps_to_vp004(self):
        assert _get_rule_id({"type": "hardcoded_secret"}) == "VP004"

    def test_high_complexity_maps_to_vp005(self):
        assert _get_rule_id({"type": "high_complexity"}) == "VP005"

    def test_js_vulnerability_maps_to_vp006(self):
        assert _get_rule_id({"type": "js_vulnerability"}) == "VP006"

    def test_unknown_type_defaults_to_vp003(self):
        assert _get_rule_id({"type": "unknown_thing"}) == "VP003"


# =========================================================================
# Test: Level mapping
# =========================================================================
class TestLevelMapping:
    """Verify severity-to-level mapping."""

    def test_high_score_is_error(self):
        assert _get_level({"vuln_score": 0.9}) == "error"

    def test_medium_score_is_warning(self):
        assert _get_level({"vuln_score": 0.6}) == "warning"

    def test_low_score_is_note(self):
        assert _get_level({"vuln_score": 0.3}) == "note"

    def test_taint_is_error(self):
        assert _get_level({"type": "taint_analysis"}) == "error"

    def test_interprocedural_is_error(self):
        assert _get_level({"type": "interprocedural_taint"}) == "error"

    def test_secret_is_error(self):
        assert _get_level({"type": "hardcoded_secret"}) == "error"

    def test_complexity_is_note(self):
        assert _get_level({"type": "high_complexity"}) == "note"

    def test_dangerous_function_is_warning(self):
        assert _get_level({"type": "dangerous_function"}) == "warning"


# =========================================================================
# Test: Message generation
# =========================================================================
class TestMessageGeneration:
    """Verify human-readable messages for each finding type."""

    def test_taint_message(self):
        msg = _get_message(TAINT_FINDING)
        assert "user_data" in msg
        assert "eval" in msg

    def test_interprocedural_message(self):
        msg = _get_message(INTERPROC_FINDING)
        assert "cmd" in msg
        assert "exec" in msg

    def test_dangerous_function_message(self):
        msg = _get_message(DANGEROUS_FUNC_FINDING)
        assert "eval" in msg

    def test_secret_message(self):
        msg = _get_message(SECRET_FINDING)
        assert "API_KEY" in msg

    def test_complexity_message(self):
        msg = _get_message(COMPLEXITY_FINDING)
        assert "25" in msg

    def test_unknown_type_fallback(self):
        msg = _get_message({"type": "custom", "message": "custom msg"})
        assert msg == "custom msg"


# =========================================================================
# Test: Result generation
# =========================================================================
class TestResultGeneration:
    """Verify SARIF result objects are correctly generated."""

    def test_result_has_rule_id(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert result["ruleId"] == "VP001"

    def test_result_has_level(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert result["level"] == "error"

    def test_result_has_message(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert "text" in result["message"]

    def test_result_has_locations(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert len(result["locations"]) == 1
        loc = result["locations"][0]
        assert "physicalLocation" in loc

    def test_location_has_artifact_uri(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app.py"
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_location_has_region(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 5
        assert region["startColumn"] == 1

    def test_result_has_fingerprint(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert "fingerprints" in result
        assert "vulnpredict/v1" in result["fingerprints"]

    def test_result_has_rule_index(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert "ruleIndex" in result
        assert isinstance(result["ruleIndex"], int)

    def test_scored_finding_has_confidence(self):
        result = _finding_to_result(SCORED_FINDING, 0, "/tmp/test")
        assert result["properties"]["confidence"] == 0.92

    def test_taint_finding_has_trace(self):
        result = _finding_to_result(TAINT_FINDING, 0, "/tmp/test")
        assert "trace" in result["properties"]

    def test_interproc_finding_has_call_chain(self):
        result = _finding_to_result(INTERPROC_FINDING, 0, "/tmp/test")
        assert "callChain" in result["properties"]


# =========================================================================
# Test: Code snippet extraction
# =========================================================================
class TestCodeSnippet:
    """Verify code snippet extraction from source files."""

    def test_snippet_from_existing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write("line1\nline2\nline3\nline4\nline5\n")
            tmppath = f.name
        try:
            snippet = _get_code_snippet(
                {"file": os.path.basename(tmppath)},
                "/tmp",
                os.path.basename(tmppath),
                3,
            )
            assert snippet is not None
            assert snippet["line"] == "line3"
            assert "context" in snippet
        finally:
            os.unlink(tmppath)

    def test_snippet_returns_none_for_missing_file(self):
        snippet = _get_code_snippet({}, "/tmp", "nonexistent.py", 1)
        assert snippet is None

    def test_snippet_context_includes_surrounding_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write("a\nb\nc\nd\ne\n")
            tmppath = f.name
        try:
            snippet = _get_code_snippet(
                {"file": os.path.basename(tmppath)},
                "/tmp",
                os.path.basename(tmppath),
                3,
            )
            assert "a" in snippet["context"]
            assert "e" in snippet["context"]
        finally:
            os.unlink(tmppath)


# =========================================================================
# Test: Full SARIF output
# =========================================================================
class TestFullSarifOutput:
    """Verify end-to-end SARIF generation."""

    def test_empty_findings_produces_valid_sarif(self):
        sarif = json.loads(format_sarif([], "/tmp/test"))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_multiple_findings_all_present(self):
        findings = [TAINT_FINDING, DANGEROUS_FUNC_FINDING, SECRET_FINDING]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        assert len(sarif["runs"][0]["results"]) == 3

    def test_rules_match_used_findings(self):
        findings = [TAINT_FINDING, COMPLEXITY_FINDING]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert "VP001" in rule_ids
        assert "VP005" in rule_ids
        assert "VP003" not in rule_ids  # Not used

    def test_output_is_valid_json(self):
        findings = [TAINT_FINDING, INTERPROC_FINDING, DANGEROUS_FUNC_FINDING]
        json.loads(format_sarif(findings, "/tmp/test"))

    def test_all_finding_types_generate_results(self):
        findings = [
            TAINT_FINDING, INTERPROC_FINDING, DANGEROUS_FUNC_FINDING,
            SECRET_FINDING, COMPLEXITY_FINDING, JS_FINDING,
        ]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        assert len(sarif["runs"][0]["results"]) == 6


# =========================================================================
# Test: write_sarif file output
# =========================================================================
class TestWriteSarif:
    """Verify write_sarif writes valid SARIF to a file."""

    def test_writes_valid_sarif_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            write_sarif([TAINT_FINDING], "/tmp/test", tmppath)
            with open(tmppath) as f:
                data = json.load(f)
            assert data["version"] == "2.1.0"
            assert len(data["runs"][0]["results"]) == 1
        finally:
            os.unlink(tmppath)

    def test_file_ends_with_newline(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            write_sarif([], "/tmp/test", tmppath)
            with open(tmppath) as f:
                content = f.read()
            assert content.endswith("\n")
        finally:
            os.unlink(tmppath)


# =========================================================================
# Test: Rule definitions
# =========================================================================
# =========================================================================
# Test: SARIF schema validation
# =========================================================================
class TestSarifSchemaValidation:
    """Validate generated SARIF against the official SARIF v2.1.0 JSON schema."""

    @pytest.fixture(scope="class")
    def sarif_schema(self):
        """Download and cache the official SARIF v2.1.0 JSON schema."""
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            pytest.skip("jsonschema not installed")
        import urllib.request
        schema_url = (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        )
        try:
            with urllib.request.urlopen(schema_url, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception:
            pytest.skip("Could not download SARIF schema")

    def test_empty_findings_validates(self, sarif_schema):
        import jsonschema
        sarif = json.loads(format_sarif([], "/tmp/test"))
        jsonschema.validate(instance=sarif, schema=sarif_schema)

    def test_single_taint_finding_validates(self, sarif_schema):
        import jsonschema
        sarif = json.loads(format_sarif([TAINT_FINDING], "/tmp/test"))
        jsonschema.validate(instance=sarif, schema=sarif_schema)

    def test_all_finding_types_validate(self, sarif_schema):
        import jsonschema
        findings = [
            TAINT_FINDING, INTERPROC_FINDING, DANGEROUS_FUNC_FINDING,
            SECRET_FINDING, COMPLEXITY_FINDING, JS_FINDING,
        ]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        jsonschema.validate(instance=sarif, schema=sarif_schema)

    def test_scored_finding_validates(self, sarif_schema):
        import jsonschema
        sarif = json.loads(format_sarif([SCORED_FINDING], "/tmp/test"))
        jsonschema.validate(instance=sarif, schema=sarif_schema)


# =========================================================================
# Test: ruleIndex correctness
# =========================================================================
class TestRuleIndex:
    """Verify ruleIndex matches the position in the filtered rules array."""

    def test_rule_index_matches_rules_array(self):
        findings = [TAINT_FINDING, COMPLEXITY_FINDING]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        for result in results:
            rule_idx = result["ruleIndex"]
            assert rules[rule_idx]["id"] == result["ruleId"]

    def test_rule_index_with_all_types(self):
        findings = [
            TAINT_FINDING, INTERPROC_FINDING, DANGEROUS_FUNC_FINDING,
            SECRET_FINDING, COMPLEXITY_FINDING, JS_FINDING,
        ]
        sarif = json.loads(format_sarif(findings, "/tmp/test"))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        for result in results:
            rule_idx = result["ruleIndex"]
            assert rule_idx < len(rules)
            assert rules[rule_idx]["id"] == result["ruleId"]


class TestRuleDefinitions:
    """Verify all rule definitions are well-formed."""

    def test_all_rules_have_required_fields(self):
        required = {"id", "name", "shortDescription", "fullDescription", "defaultConfiguration"}
        for rule_id, rule in RULES.items():
            assert required.issubset(rule.keys()), f"Rule {rule_id} missing: {required - rule.keys()}"

    def test_all_rules_have_tags(self):
        for rule_id, rule in RULES.items():
            assert "tags" in rule.get("properties", {}), f"Rule {rule_id} missing tags"

    def test_rule_ids_are_sequential(self):
        ids = sorted(RULES.keys())
        for i, rid in enumerate(ids):
            expected = f"VP{i + 1:03d}"
            assert rid == expected, f"Expected {expected}, got {rid}"
