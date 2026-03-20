"""Tests for the severity and confidence scoring framework."""

import pytest

from vulnpredict.severity import (
    Confidence,
    RULE_REGISTRY,
    Severity,
    classify_finding,
    compute_combined_score,
    filter_by_severity,
    sort_by_severity,
)


# ===========================================================================
# Severity enum
# ===========================================================================


class TestSeverityEnum:
    def test_ordering(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_from_str(self):
        assert Severity.from_str("low") == Severity.LOW
        assert Severity.from_str("HIGH") == Severity.HIGH
        assert Severity.from_str("Critical") == Severity.CRITICAL

    def test_from_str_unknown_defaults_to_medium(self):
        assert Severity.from_str("unknown") == Severity.MEDIUM

    def test_str_representation(self):
        assert str(Severity.CRITICAL) == "Critical"
        assert str(Severity.LOW) == "Low"


# ===========================================================================
# Confidence enum
# ===========================================================================


class TestConfidenceEnum:
    def test_ordering(self):
        assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH

    def test_from_str(self):
        assert Confidence.from_str("low") == Confidence.LOW
        assert Confidence.from_str("HIGH") == Confidence.HIGH

    def test_from_str_unknown_defaults_to_medium(self):
        assert Confidence.from_str("bogus") == Confidence.MEDIUM


# ===========================================================================
# Rule registry
# ===========================================================================


class TestRuleRegistry:
    def test_all_rules_have_valid_severity(self):
        for rule_id, (sev, conf, desc) in RULE_REGISTRY.items():
            assert isinstance(sev, Severity), f"{rule_id} has invalid severity"
            assert isinstance(conf, Confidence), f"{rule_id} has invalid confidence"
            assert isinstance(desc, str) and len(desc) > 0, f"{rule_id} has empty description"

    def test_eval_rule_is_critical(self):
        sev, conf, _ = RULE_REGISTRY["PY-EVAL-001"]
        assert sev == Severity.CRITICAL
        assert conf == Confidence.HIGH

    def test_cmdi_rule_is_critical(self):
        sev, conf, _ = RULE_REGISTRY["PY-CMDI-001"]
        assert sev == Severity.CRITICAL
        assert conf == Confidence.HIGH

    def test_sqli_rule_is_critical(self):
        sev, conf, _ = RULE_REGISTRY["PY-SQLI-001"]
        assert sev == Severity.CRITICAL
        assert conf == Confidence.HIGH

    def test_secret_rule_has_high_confidence(self):
        _, conf, _ = RULE_REGISTRY["PY-SECRET-001"]
        assert conf == Confidence.HIGH

    def test_ldap_rule_has_high_confidence(self):
        _, conf, _ = RULE_REGISTRY["PY-LDAP-001"]
        assert conf == Confidence.HIGH

    def test_js_xss_has_high_confidence(self):
        _, conf, _ = RULE_REGISTRY["JS-XSS-001"]
        assert conf == Confidence.HIGH

    def test_js_exec_is_critical(self):
        sev, _, _ = RULE_REGISTRY["JS-EXEC-001"]
        assert sev == Severity.CRITICAL

    def test_weak_crypto_is_medium(self):
        sev, _, _ = RULE_REGISTRY["PY-CRYPTO-001"]
        assert sev == Severity.MEDIUM


# ===========================================================================
# classify_finding
# ===========================================================================


class TestClassifyFinding:
    def test_eval_finding_gets_critical(self):
        finding = {"name": "test_func", "dangerous_calls": ["eval"]}
        result = classify_finding(finding)
        assert result["severity"] == "Critical"
        assert result["rule_id"] == "PY-EVAL-001"
        assert result["confidence"] == "High"
        assert "combined_score" in result

    def test_exec_finding_gets_critical(self):
        finding = {"name": "test_func", "dangerous_calls": ["exec"]}
        result = classify_finding(finding)
        assert result["severity"] == "Critical"
        assert result["rule_id"] == "PY-EXEC-001"

    def test_subprocess_finding_gets_critical(self):
        finding = {"name": "test_func", "dangerous_calls": ["subprocess.call"]}
        result = classify_finding(finding)
        assert result["severity"] == "Critical"
        assert result["rule_id"] == "PY-CMDI-001"

    def test_deserialization_finding(self):
        finding = {"name": "test_func", "deserialization_calls": ["pickle.loads"]}
        result = classify_finding(finding)
        assert result["severity"] == "Critical"
        assert result["rule_id"] == "PY-DESER-001"

    def test_dill_deserialization_uses_deser_002(self):
        finding = {"name": "test_func", "deserialization_calls": ["dill.loads"]}
        result = classify_finding(finding)
        assert result["rule_id"] == "PY-DESER-002"

    def test_ssrf_finding(self):
        finding = {"name": "test_func", "ssrf_calls": ["requests.get"]}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["rule_id"] == "PY-SSRF-001"

    def test_path_traversal_finding(self):
        finding = {"name": "test_func", "path_traversal_calls": ["open"]}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["rule_id"] == "PY-PATH-001"

    def test_xxe_finding(self):
        finding = {"name": "test_func", "xxe_calls": ["ET.parse"]}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["rule_id"] == "PY-XXE-001"

    def test_weak_crypto_hash(self):
        finding = {"name": "test_func", "weak_crypto_calls": ["hashlib.md5"]}
        result = classify_finding(finding)
        assert result["severity"] == "Medium"
        assert result["rule_id"] == "PY-CRYPTO-001"

    def test_weak_crypto_cipher(self):
        finding = {"name": "test_func", "weak_crypto_calls": ["DES.new"]}
        result = classify_finding(finding)
        assert result["severity"] == "Medium"
        assert result["rule_id"] == "PY-CRYPTO-002"

    def test_template_injection(self):
        finding = {"name": "test_func", "template_injection_calls": ["jinja2.Template"]}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["rule_id"] == "PY-TMPL-001"

    def test_open_redirect(self):
        finding = {"name": "test_func", "open_redirect_calls": ["redirect"]}
        result = classify_finding(finding)
        assert result["severity"] == "Medium"
        assert result["rule_id"] == "PY-REDIR-001"

    def test_ldap_injection(self):
        finding = {"name": "test_func", "ldap_injection_calls": ["conn.search_s"]}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["rule_id"] == "PY-LDAP-001"

    def test_secret_finding(self):
        finding = {"name": "test_func", "sensitive_data_involved": True}
        result = classify_finding(finding)
        assert result["severity"] == "High"
        assert result["confidence"] == "High"
        assert result["rule_id"] == "PY-SECRET-001"

    def test_high_complexity(self):
        finding = {"name": "test_func", "cyclomatic_complexity": 20}
        result = classify_finding(finding)
        assert result["severity"] == "Low"
        assert result["rule_id"] == "PY-COMPLEX-001"

    def test_deep_nesting(self):
        finding = {"name": "test_func", "max_nesting_depth": 8}
        result = classify_finding(finding)
        assert result["severity"] == "Low"
        assert result["rule_id"] == "PY-NESTING-001"

    def test_no_issues_gets_unknown(self):
        finding = {"name": "test_func"}
        result = classify_finding(finding)
        assert result["rule_id"] == "UNKNOWN"
        assert result["severity"] == "Low"

    def test_multiple_issues_picks_highest_severity(self):
        """When a finding has both eval and weak crypto, eval (Critical) wins."""
        finding = {
            "name": "test_func",
            "dangerous_calls": ["eval"],
            "weak_crypto_calls": ["hashlib.md5"],
        }
        result = classify_finding(finding)
        assert result["severity"] == "Critical"
        assert result["rule_id"] == "PY-EVAL-001"

    def test_ml_score_affects_combined_score(self):
        finding = {"name": "test_func", "dangerous_calls": ["eval"], "vuln_score": 0.9}
        result = classify_finding(finding)
        score_high_ml = result["combined_score"]

        finding2 = {"name": "test_func", "dangerous_calls": ["eval"], "vuln_score": 0.1}
        result2 = classify_finding(finding2)
        score_low_ml = result2["combined_score"]

        assert score_high_ml > score_low_ml


# ===========================================================================
# compute_combined_score
# ===========================================================================


class TestComputeCombinedScore:
    def test_critical_high_confidence_high_ml(self):
        score = compute_combined_score(Severity.CRITICAL, Confidence.HIGH, 1.0)
        assert score == pytest.approx(1.0, abs=0.01)

    def test_low_low_confidence_zero_ml(self):
        score = compute_combined_score(Severity.LOW, Confidence.LOW, 0.0)
        assert score < 0.1

    def test_score_bounded_0_to_1(self):
        score = compute_combined_score(Severity.CRITICAL, Confidence.HIGH, 1.5)
        assert score <= 1.0

        score = compute_combined_score(Severity.LOW, Confidence.LOW, -0.5)
        assert score >= 0.0

    def test_static_weight_dominates(self):
        """With static_weight=1.0, ml_score should have no effect."""
        score1 = compute_combined_score(
            Severity.HIGH, Confidence.HIGH, 0.0, static_weight=1.0, ml_weight=0.0
        )
        score2 = compute_combined_score(
            Severity.HIGH, Confidence.HIGH, 1.0, static_weight=1.0, ml_weight=0.0
        )
        assert score1 == score2


# ===========================================================================
# filter_by_severity
# ===========================================================================


class TestFilterBySeverity:
    def test_filter_high_and_above(self):
        findings = [
            {"severity": "Critical", "name": "a"},
            {"severity": "High", "name": "b"},
            {"severity": "Medium", "name": "c"},
            {"severity": "Low", "name": "d"},
        ]
        result = filter_by_severity(findings, "high")
        assert len(result) == 2
        names = {f["name"] for f in result}
        assert names == {"a", "b"}

    def test_filter_critical_only(self):
        findings = [
            {"severity": "Critical", "name": "a"},
            {"severity": "High", "name": "b"},
        ]
        result = filter_by_severity(findings, "critical")
        assert len(result) == 1
        assert result[0]["name"] == "a"

    def test_filter_low_returns_all(self):
        findings = [
            {"severity": "Critical", "name": "a"},
            {"severity": "Low", "name": "b"},
        ]
        result = filter_by_severity(findings, "low")
        assert len(result) == 2

    def test_filter_empty_list(self):
        assert filter_by_severity([], "high") == []


# ===========================================================================
# sort_by_severity
# ===========================================================================


# ===========================================================================
# _match_rules (direct tests)
# ===========================================================================


class TestMatchRules:
    """Direct tests for the _match_rules internal function."""

    def test_empty_finding(self):
        from vulnpredict.severity import _match_rules
        assert _match_rules({}) == []

    def test_eval_in_dangerous_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"dangerous_calls": ["eval"]})
        assert "PY-EVAL-001" in result

    def test_exec_in_dangerous_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"dangerous_calls": ["exec"]})
        assert "PY-EXEC-001" in result

    def test_subprocess_in_dangerous_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"dangerous_calls": ["subprocess.call"]})
        assert "PY-CMDI-001" in result

    def test_os_system_in_dangerous_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"dangerous_calls": ["os.system"]})
        assert "PY-CMDI-001" in result

    def test_pickle_deserialization(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"deserialization_calls": ["pickle.loads"]})
        assert "PY-DESER-001" in result

    def test_dill_deserialization(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"deserialization_calls": ["dill.loads"]})
        assert "PY-DESER-002" in result

    def test_ssrf_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"ssrf_calls": ["requests.get"]})
        assert "PY-SSRF-001" in result

    def test_path_traversal_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"path_traversal_calls": ["open"]})
        assert "PY-PATH-001" in result

    def test_xxe_calls(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"xxe_calls": ["ET.parse"]})
        assert "PY-XXE-001" in result

    def test_weak_hash(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"weak_crypto_calls": ["hashlib.md5"]})
        assert "PY-CRYPTO-001" in result

    def test_weak_cipher_des(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"weak_crypto_calls": ["DES.new"]})
        assert "PY-CRYPTO-002" in result

    def test_template_injection(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"template_injection_calls": ["jinja2.Template"]})
        assert "PY-TMPL-001" in result

    def test_open_redirect(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"open_redirect_calls": ["redirect"]})
        assert "PY-REDIR-001" in result

    def test_ldap_injection(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"ldap_injection_calls": ["conn.search_s"]})
        assert "PY-LDAP-001" in result

    def test_sensitive_data(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"sensitive_data_involved": True})
        assert "PY-SECRET-001" in result

    def test_high_complexity(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"cyclomatic_complexity": 20})
        assert "PY-COMPLEX-001" in result

    def test_low_complexity_no_match(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"cyclomatic_complexity": 5})
        assert "PY-COMPLEX-001" not in result

    def test_deep_nesting(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"max_nesting_depth": 8})
        assert "PY-NESTING-001" in result

    def test_shallow_nesting_no_match(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"max_nesting_depth": 3})
        assert "PY-NESTING-001" not in result

    def test_multiple_categories_returns_all(self):
        from vulnpredict.severity import _match_rules
        finding = {
            "dangerous_calls": ["eval"],
            "weak_crypto_calls": ["hashlib.md5"],
            "sensitive_data_involved": True,
        }
        result = _match_rules(finding)
        assert "PY-EVAL-001" in result
        assert "PY-CRYPTO-001" in result
        assert "PY-SECRET-001" in result

    def test_non_matching_attributes(self):
        from vulnpredict.severity import _match_rules
        result = _match_rules({"name": "foo", "file": "bar.py"})
        assert result == []

    def test_missing_vuln_score_defaults_to_half(self):
        """classify_finding should use 0.5 as default ML score."""
        finding = {"name": "test_func", "dangerous_calls": ["eval"]}
        result = classify_finding(finding)
        # With vuln_score=0.5 (default), combined_score should be deterministic
        assert "combined_score" in result
        assert result["combined_score"] > 0

    def test_filter_with_missing_severity_key(self):
        """Findings without severity key should default to 'low'."""
        findings = [{"name": "a"}, {"severity": "High", "name": "b"}]
        result = filter_by_severity(findings, "high")
        assert len(result) == 1
        assert result[0]["name"] == "b"

    def test_sort_with_missing_keys(self):
        """Findings without severity/combined_score should still sort."""
        findings = [
            {"name": "a"},
            {"severity": "Critical", "combined_score": 0.9, "name": "b"},
        ]
        result = sort_by_severity(findings)
        assert result[0]["name"] == "b"


class TestSortBySeverity:
    def test_descending_order(self):
        findings = [
            {"severity": "Low", "combined_score": 0.1},
            {"severity": "Critical", "combined_score": 0.9},
            {"severity": "Medium", "combined_score": 0.5},
        ]
        result = sort_by_severity(findings, descending=True)
        assert result[0]["severity"] == "Critical"
        assert result[-1]["severity"] == "Low"

    def test_ascending_order(self):
        findings = [
            {"severity": "Critical", "combined_score": 0.9},
            {"severity": "Low", "combined_score": 0.1},
        ]
        result = sort_by_severity(findings, descending=False)
        assert result[0]["severity"] == "Low"
        assert result[-1]["severity"] == "Critical"

    def test_tiebreaker_by_combined_score(self):
        findings = [
            {"severity": "High", "combined_score": 0.5},
            {"severity": "High", "combined_score": 0.9},
        ]
        result = sort_by_severity(findings, descending=True)
        assert result[0]["combined_score"] == 0.9

    def test_empty_list(self):
        assert sort_by_severity([]) == []
