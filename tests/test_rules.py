"""Unit tests for the configurable rule engine (vulnpredict.rules)."""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

import pytest

from vulnpredict.rules import (
    BUILTIN_RULES_DIR,
    Rule,
    RuleIndex,
    RulePattern,
    RuleValidationError,
    load_all_rules,
    load_rules_from_directory,
    load_rules_from_file,
    validate_rule_dict,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_RULE_YAML = """\
rules:
  - id: TEST-001
    name: test-eval
    severity: critical
    confidence: high
    languages: [python]
    message: "Use of eval()"
    pattern:
      type: function_call
      name: eval
    cwe: CWE-95
    tags: [injection]
    references:
      - https://example.com
  - id: TEST-002
    name: test-exec
    severity: high
    confidence: medium
    languages: [python]
    message: "Use of exec()"
    pattern:
      type: function_call
      name: exec
    cwe: CWE-95
"""

MULTI_NAME_RULE_YAML = """\
rules:
  - id: TEST-010
    name: test-subprocess
    severity: high
    confidence: medium
    languages: [python]
    message: "Subprocess call"
    pattern:
      type: function_call
      names:
        - subprocess.Popen
        - subprocess.call
        - subprocess.run
"""

DISABLED_RULE_YAML = """\
rules:
  - id: TEST-DISABLED
    name: disabled-rule
    severity: low
    message: "This rule is disabled"
    enabled: false
    pattern:
      type: function_call
      name: some_func
"""


def _write_yaml(content: str, directory: str, filename: str = "test.yml") -> str:
    """Write YAML content to a file and return the path."""
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# RulePattern tests
# ---------------------------------------------------------------------------


class TestRulePattern:
    """Tests for the RulePattern dataclass."""

    def test_matches_single_name(self) -> None:
        p = RulePattern(type="function_call", name="eval")
        assert p.matches_function("eval")
        assert not p.matches_function("exec")

    def test_matches_multiple_names(self) -> None:
        p = RulePattern(type="function_call", names=["eval", "exec"])
        assert p.matches_function("eval")
        assert p.matches_function("exec")
        assert not p.matches_function("compile")

    def test_non_function_call_does_not_match(self) -> None:
        p = RulePattern(type="import", name="eval")
        assert not p.matches_function("eval")

    def test_get_all_names(self) -> None:
        p = RulePattern(type="function_call", name="eval", names=["exec", "compile"])
        names = p.get_all_names()
        assert names == {"eval", "exec", "compile"}

    def test_get_all_names_empty(self) -> None:
        p = RulePattern(type="import")
        assert p.get_all_names() == set()


# ---------------------------------------------------------------------------
# Rule tests
# ---------------------------------------------------------------------------


class TestRule:
    """Tests for the Rule dataclass."""

    def test_rule_description_with_cwe(self) -> None:
        r = Rule(
            id="T-1", name="test", severity="high",
            message="Test message", pattern=RulePattern(type="function_call"),
            cwe="CWE-79",
        )
        assert r.rule_description == "Test message (CWE-79)"

    def test_rule_description_without_cwe(self) -> None:
        r = Rule(
            id="T-1", name="test", severity="high",
            message="Test message", pattern=RulePattern(type="function_call"),
        )
        assert r.rule_description == "Test message"


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestValidateRuleDict:
    """Tests for rule validation."""

    def test_valid_rule(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1",
            "name": "test",
            "severity": "high",
            "message": "Test",
            "pattern": {"type": "function_call", "name": "eval"},
        }
        errors = validate_rule_dict(data)
        assert errors == []

    def test_missing_required_fields(self) -> None:
        errors = validate_rule_dict({})
        assert len(errors) >= len({"id", "name", "severity", "message", "pattern"})

    def test_invalid_severity(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1", "name": "test", "severity": "extreme",
            "message": "Test", "pattern": {"type": "function_call", "name": "eval"},
        }
        errors = validate_rule_dict(data)
        assert any("severity" in e for e in errors)

    def test_invalid_confidence(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1", "name": "test", "severity": "high",
            "confidence": "very-high",
            "message": "Test", "pattern": {"type": "function_call", "name": "eval"},
        }
        errors = validate_rule_dict(data)
        assert any("confidence" in e for e in errors)

    def test_invalid_pattern_type(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1", "name": "test", "severity": "high",
            "message": "Test", "pattern": {"type": "invalid_type", "name": "eval"},
        }
        errors = validate_rule_dict(data)
        assert any("pattern type" in e for e in errors)

    def test_function_call_without_name(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1", "name": "test", "severity": "high",
            "message": "Test", "pattern": {"type": "function_call"},
        }
        errors = validate_rule_dict(data)
        assert any("name" in e for e in errors)

    def test_unsupported_language(self) -> None:
        data: Dict[str, Any] = {
            "id": "T-1", "name": "test", "severity": "high",
            "message": "Test", "pattern": {"type": "function_call", "name": "eval"},
            "languages": ["rust"],
        }
        errors = validate_rule_dict(data)
        assert any("language" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Loading tests
# ---------------------------------------------------------------------------


class TestLoadRulesFromFile:
    """Tests for loading rules from YAML files."""

    def test_load_valid_file(self, tmp_path: Any) -> None:
        path = _write_yaml(VALID_RULE_YAML, str(tmp_path))
        rules = load_rules_from_file(path)
        assert len(rules) == 2
        assert rules[0].id == "TEST-001"
        assert rules[0].severity == "critical"
        assert rules[0].cwe == "CWE-95"
        assert rules[1].id == "TEST-002"

    def test_load_multi_name_rule(self, tmp_path: Any) -> None:
        path = _write_yaml(MULTI_NAME_RULE_YAML, str(tmp_path))
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        assert rules[0].pattern.names == ["subprocess.Popen", "subprocess.call", "subprocess.run"]

    def test_disabled_rule_skipped(self, tmp_path: Any) -> None:
        path = _write_yaml(DISABLED_RULE_YAML, str(tmp_path))
        rules = load_rules_from_file(path)
        assert len(rules) == 0

    def test_invalid_yaml_non_strict(self, tmp_path: Any) -> None:
        path = _write_yaml("{{invalid yaml", str(tmp_path))
        rules = load_rules_from_file(path, strict=False)
        assert rules == []

    def test_invalid_yaml_strict_raises(self, tmp_path: Any) -> None:
        path = _write_yaml("{{invalid yaml", str(tmp_path))
        with pytest.raises(RuleValidationError):
            load_rules_from_file(path, strict=True)

    def test_missing_rules_key(self, tmp_path: Any) -> None:
        path = _write_yaml("not_rules: []", str(tmp_path))
        rules = load_rules_from_file(path, strict=False)
        assert rules == []

    def test_missing_rules_key_strict(self, tmp_path: Any) -> None:
        path = _write_yaml("not_rules: []", str(tmp_path))
        with pytest.raises(RuleValidationError):
            load_rules_from_file(path, strict=True)

    def test_nonexistent_file(self) -> None:
        rules = load_rules_from_file("/nonexistent/rules.yml")
        assert rules == []

    def test_nonexistent_file_strict(self) -> None:
        with pytest.raises(RuleValidationError):
            load_rules_from_file("/nonexistent/rules.yml", strict=True)

    def test_source_file_tracked(self, tmp_path: Any) -> None:
        path = _write_yaml(VALID_RULE_YAML, str(tmp_path))
        rules = load_rules_from_file(path)
        assert rules[0].source_file == path


class TestLoadRulesFromDirectory:
    """Tests for loading rules from a directory."""

    def test_load_from_directory(self, tmp_path: Any) -> None:
        _write_yaml(VALID_RULE_YAML, str(tmp_path), "rules1.yml")
        _write_yaml(MULTI_NAME_RULE_YAML, str(tmp_path), "rules2.yaml")
        rules = load_rules_from_directory(str(tmp_path))
        assert len(rules) == 3  # 2 from rules1 + 1 from rules2

    def test_ignores_non_yaml_files(self, tmp_path: Any) -> None:
        _write_yaml(VALID_RULE_YAML, str(tmp_path), "rules.yml")
        # Write a non-YAML file
        with open(os.path.join(str(tmp_path), "readme.txt"), "w") as f:
            f.write("not a rule file")
        rules = load_rules_from_directory(str(tmp_path))
        assert len(rules) == 2

    def test_nonexistent_directory(self) -> None:
        rules = load_rules_from_directory("/nonexistent/dir")
        assert rules == []


class TestLoadAllRules:
    """Tests for loading built-in + user rules."""

    def test_loads_builtin_rules(self) -> None:
        rules = load_all_rules()
        assert len(rules) > 0
        # Should have some Python rules
        py_rules = [r for r in rules if "python" in r.languages]
        assert len(py_rules) > 5

    def test_user_rules_override_builtin(self, tmp_path: Any) -> None:
        # Create a user rule with the same ID as a built-in rule
        override_yaml = """\
rules:
  - id: VP-PY-001
    name: custom-eval
    severity: low
    message: "Custom eval rule"
    pattern:
      type: function_call
      name: eval
"""
        _write_yaml(override_yaml, str(tmp_path))
        rules = load_all_rules(extra_dirs=[str(tmp_path)])
        # Find the VP-PY-001 rule
        matched = [r for r in rules if r.id == "VP-PY-001"]
        assert len(matched) == 1
        assert matched[0].name == "custom-eval"
        assert matched[0].severity == "low"

    def test_extra_dirs_add_rules(self, tmp_path: Any) -> None:
        custom_yaml = """\
rules:
  - id: CUSTOM-001
    name: custom-rule
    severity: medium
    message: "Custom rule"
    pattern:
      type: function_call
      name: custom_func
"""
        _write_yaml(custom_yaml, str(tmp_path))
        rules = load_all_rules(extra_dirs=[str(tmp_path)])
        custom = [r for r in rules if r.id == "CUSTOM-001"]
        assert len(custom) == 1


# ---------------------------------------------------------------------------
# RuleIndex tests
# ---------------------------------------------------------------------------


class TestRuleIndex:
    """Tests for the RuleIndex class."""

    def test_function_name_lookup(self) -> None:
        rules = [
            Rule(
                id="T-1", name="test", severity="high", message="Test",
                pattern=RulePattern(type="function_call", name="eval"),
                languages=["python"],
            ),
            Rule(
                id="T-2", name="test2", severity="medium", message="Test2",
                pattern=RulePattern(type="function_call", names=["exec", "compile"]),
                languages=["python"],
            ),
        ]
        idx = RuleIndex(rules)
        assert len(idx.match_function_call("eval")) == 1
        assert idx.match_function_call("eval")[0].id == "T-1"
        assert len(idx.match_function_call("exec")) == 1
        assert len(idx.match_function_call("compile")) == 1
        assert len(idx.match_function_call("unknown")) == 0

    def test_language_filtering(self) -> None:
        rules = [
            Rule(
                id="T-1", name="test", severity="high", message="Test",
                pattern=RulePattern(type="function_call", name="eval"),
                languages=["python"],
            ),
            Rule(
                id="T-2", name="test2", severity="high", message="Test2",
                pattern=RulePattern(type="function_call", name="eval"),
                languages=["javascript"],
            ),
        ]
        idx = RuleIndex(rules)
        py_matches = idx.match_function_call("eval", language="python")
        assert len(py_matches) == 1
        assert py_matches[0].id == "T-1"

        js_matches = idx.match_function_call("eval", language="javascript")
        assert len(js_matches) == 1
        assert js_matches[0].id == "T-2"

    def test_function_names_property(self) -> None:
        rules = [
            Rule(
                id="T-1", name="test", severity="high", message="Test",
                pattern=RulePattern(type="function_call", name="eval", names=["exec"]),
            ),
        ]
        idx = RuleIndex(rules)
        assert idx.function_names == {"eval", "exec"}

    def test_get_rules_by_language(self) -> None:
        rules = [
            Rule(id="T-1", name="t1", severity="high", message="M",
                 pattern=RulePattern(type="function_call"), languages=["python"]),
            Rule(id="T-2", name="t2", severity="high", message="M",
                 pattern=RulePattern(type="function_call"), languages=["javascript"]),
            Rule(id="T-3", name="t3", severity="high", message="M",
                 pattern=RulePattern(type="function_call"), languages=["python", "javascript"]),
        ]
        idx = RuleIndex(rules)
        py_rules = idx.get_rules_by_language("python")
        assert len(py_rules) == 2

    def test_get_rule_by_id(self) -> None:
        rules = [
            Rule(id="T-1", name="t1", severity="high", message="M",
                 pattern=RulePattern(type="function_call")),
        ]
        idx = RuleIndex(rules)
        assert idx.get_rule_by_id("T-1") is not None
        assert idx.get_rule_by_id("T-1").name == "t1"
        assert idx.get_rule_by_id("NONEXISTENT") is None

    def test_len(self) -> None:
        rules = [
            Rule(id="T-1", name="t1", severity="high", message="M",
                 pattern=RulePattern(type="function_call")),
            Rule(id="T-2", name="t2", severity="high", message="M",
                 pattern=RulePattern(type="function_call")),
        ]
        idx = RuleIndex(rules)
        assert len(idx) == 2

    def test_builtin_rules_index(self) -> None:
        """Verify built-in rules can be indexed and looked up."""
        rules = load_all_rules()
        idx = RuleIndex(rules)
        assert len(idx) > 0
        # Should find eval in function names
        assert "eval" in idx.function_names
        # Should match eval for Python
        matches = idx.match_function_call("eval", language="python")
        assert len(matches) >= 1
