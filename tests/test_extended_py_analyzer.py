"""Tests for extended vulnerability detection patterns in py_analyzer.py.

Covers: deserialization, SSRF, path traversal, XXE, weak crypto,
template injection, open redirect, LDAP injection.
"""

import ast
import os

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "python", "extended")


# ---------------------------------------------------------------------------
# Helper: run FunctionAnalyzer on a fixture file
# ---------------------------------------------------------------------------

def _analyze_fixture(filename):
    """Parse a fixture file and return the list of function info dicts."""
    from vulnpredict.py_analyzer import FunctionAnalyzer

    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath) as f:
        source = f.read()
    tree = ast.parse(source, filename=filepath)
    analyzer = FunctionAnalyzer()
    analyzer.visit(tree)
    return analyzer.functions


def _find_func(functions, name):
    """Find a function info dict by name."""
    for f in functions:
        if f["name"] == name:
            return f
    raise ValueError(f"Function {name!r} not found in {[f['name'] for f in functions]}")


# ===========================================================================
# Deserialization
# ===========================================================================

class TestDeserialization:
    def test_detects_pickle_loads(self):
        funcs = _analyze_fixture("vuln_deserialization.py")
        f = _find_func(funcs, "load_user_data")
        assert "pickle.loads" in f["deserialization_calls"]

    def test_detects_yaml_load_without_safe_loader(self):
        funcs = _analyze_fixture("vuln_deserialization.py")
        f = _find_func(funcs, "load_yaml_unsafe")
        assert "yaml.load" in f["deserialization_calls"]

    def test_detects_marshal_loads(self):
        funcs = _analyze_fixture("vuln_deserialization.py")
        f = _find_func(funcs, "load_marshal_data")
        assert "marshal.loads" in f["deserialization_calls"]

    def test_safe_yaml_load_with_safe_loader(self):
        funcs = _analyze_fixture("safe_deserialization.py")
        f = _find_func(funcs, "load_yaml_safe")
        assert f["deserialization_calls"] == []

    def test_safe_json_loads(self):
        funcs = _analyze_fixture("safe_deserialization.py")
        f = _find_func(funcs, "load_json_data")
        assert f["deserialization_calls"] == []


# ===========================================================================
# SSRF
# ===========================================================================

class TestSSRF:
    def test_detects_requests_get(self):
        funcs = _analyze_fixture("vuln_ssrf.py")
        f = _find_func(funcs, "fetch_url")
        assert "requests.get" in f["ssrf_calls"]

    def test_detects_urllib_urlopen(self):
        funcs = _analyze_fixture("vuln_ssrf.py")
        f = _find_func(funcs, "fetch_with_urllib")
        assert "urllib.request.urlopen" in f["ssrf_calls"]


# ===========================================================================
# Path Traversal
# ===========================================================================

class TestPathTraversal:
    def test_detects_open(self):
        funcs = _analyze_fixture("vuln_path_traversal.py")
        f = _find_func(funcs, "read_user_file")
        assert "open" in f["path_traversal_calls"]

    def test_detects_open_after_join(self):
        """os.path.join is a path constructor, not a sink.
        The actual sink is the open() call that uses the joined path."""
        funcs = _analyze_fixture("vuln_path_traversal.py")
        f = _find_func(funcs, "join_user_path")
        assert "open" in f["path_traversal_calls"]
        # os.path.join should NOT be flagged as a sink
        assert "os.path.join" not in f["path_traversal_calls"]

    def test_detects_shutil_rmtree(self):
        funcs = _analyze_fixture("vuln_path_traversal.py")
        f = _find_func(funcs, "delete_user_file")
        assert "shutil.rmtree" in f["path_traversal_calls"]


# ===========================================================================
# XXE
# ===========================================================================

class TestXXE:
    def test_detects_et_parse(self):
        funcs = _analyze_fixture("vuln_xxe.py")
        f = _find_func(funcs, "parse_xml_file")
        # The import alias means the call resolves to ET.parse
        assert any("parse" in c for c in f["xxe_calls"])

    def test_detects_et_fromstring(self):
        funcs = _analyze_fixture("vuln_xxe.py")
        f = _find_func(funcs, "parse_xml_string")
        assert any("fromstring" in c for c in f["xxe_calls"])


# ===========================================================================
# Weak Crypto
# ===========================================================================

class TestWeakCrypto:
    def test_detects_md5(self):
        funcs = _analyze_fixture("vuln_weak_crypto.py")
        f = _find_func(funcs, "hash_password_md5")
        assert "hashlib.md5" in f["weak_crypto_calls"]

    def test_detects_sha1(self):
        funcs = _analyze_fixture("vuln_weak_crypto.py")
        f = _find_func(funcs, "hash_token_sha1")
        assert "hashlib.sha1" in f["weak_crypto_calls"]


# ===========================================================================
# Template Injection
# ===========================================================================

class TestTemplateInjection:
    def test_detects_jinja2_template(self):
        funcs = _analyze_fixture("vuln_template_injection.py")
        f = _find_func(funcs, "render_user_template")
        assert "jinja2.Template" in f["template_injection_calls"]


# ===========================================================================
# Open Redirect
# ===========================================================================

class TestOpenRedirect:
    def test_detects_flask_redirect(self):
        funcs = _analyze_fixture("vuln_open_redirect.py")
        f = _find_func(funcs, "handle_redirect")
        assert "redirect" in f["open_redirect_calls"]


# ===========================================================================
# LDAP Injection
# ===========================================================================

class TestLDAPInjection:
    def test_detects_ldap_search(self):
        funcs = _analyze_fixture("vuln_ldap_injection.py")
        f = _find_func(funcs, "search_user")
        # conn.search_s resolves to the attribute chain
        assert any("search_s" in c for c in f["ldap_injection_calls"])


# ===========================================================================
# Integration: analyze_python_file picks up extended patterns
# ===========================================================================

class TestAnalyzePythonFileExtended:
    def test_deserialization_in_findings(self):
        from vulnpredict.py_analyzer import analyze_python_file

        filepath = os.path.join(FIXTURES_DIR, "vuln_deserialization.py")
        findings = analyze_python_file(filepath)
        deser_findings = [
            f for f in findings
            if f.get("deserialization_calls")
        ]
        assert len(deser_findings) >= 1

    def test_weak_crypto_in_findings(self):
        from vulnpredict.py_analyzer import analyze_python_file

        filepath = os.path.join(FIXTURES_DIR, "vuln_weak_crypto.py")
        findings = analyze_python_file(filepath)
        crypto_findings = [
            f for f in findings
            if f.get("weak_crypto_calls")
        ]
        assert len(crypto_findings) >= 1

    def test_safe_file_no_extended_findings(self):
        from vulnpredict.py_analyzer import analyze_python_file

        filepath = os.path.join(FIXTURES_DIR, "safe_deserialization.py")
        findings = analyze_python_file(filepath)
        # Safe files should not produce deserialization findings
        deser_findings = [
            f for f in findings
            if f.get("deserialization_calls")
        ]
        assert len(deser_findings) == 0


# ===========================================================================
# _has_safe_loader edge cases
# ===========================================================================

class TestHasSafeLoader:
    def test_safe_loader_as_attribute(self):
        """yaml.load(text, Loader=yaml.SafeLoader) should be safe."""
        code = "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.SafeLoader)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert f["deserialization_calls"] == []

    def test_safe_loader_as_name(self):
        """yaml.load(text, Loader=SafeLoader) should be safe."""
        code = "import yaml\nfrom yaml import SafeLoader\ndef f(t):\n    return yaml.load(t, Loader=SafeLoader)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert f["deserialization_calls"] == []

    def test_csafe_loader(self):
        """yaml.load(text, Loader=yaml.CSafeLoader) should be safe."""
        code = "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.CSafeLoader)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert f["deserialization_calls"] == []

    def test_full_loader_is_unsafe(self):
        """yaml.load(text, Loader=yaml.FullLoader) should still be flagged."""
        code = "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.FullLoader)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert "yaml.load" in f["deserialization_calls"]


# ===========================================================================
# Regression: existing detections still work
# ===========================================================================

class TestRegressionExistingDetections:
    def test_eval_still_detected(self):
        code = "def f(x):\n    return eval(x)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert "eval" in f["dangerous_calls"]

    def test_subprocess_still_detected(self):
        code = "import subprocess\ndef f(cmd):\n    subprocess.call(cmd)\n"
        tree = ast.parse(code)
        from vulnpredict.py_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)
        f = _find_func(analyzer.functions, "f")
        assert "subprocess.call" in f["dangerous_calls"]
