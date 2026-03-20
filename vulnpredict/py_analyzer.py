import ast
import datetime
import os
import re
import subprocess

import requests
import torch
from transformers import AutoModel, AutoTokenizer

DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
    "execfile",
    "input",
    "os.system",
    "subprocess.Popen",
    "subprocess.call",
}
VALIDATION_MODULES = {"re", "json", "html", "bleach"}
VALIDATION_FUNCTIONS = {"escape", "loads", "dumps", "clean", "fullmatch", "match", "search", "sub", "subn"}

# --- Extended vulnerability patterns ---

# Deserialization sinks — loading untrusted data can lead to RCE
DESERIALIZATION_SINKS = {
    "pickle.loads",
    "pickle.load",
    "pickle.Unpickler",
    "cPickle.loads",
    "cPickle.load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
    "yaml.load",          # safe only with Loader=SafeLoader
    "yaml.unsafe_load",
    "jsonpickle.decode",
    "dill.loads",
    "dill.load",
    "cloudpickle.loads",
    "cloudpickle.load",
    # from-import aliases
    "loads",  # from pickle import loads
    "load",   # from pickle import load
}

# SSRF sinks — HTTP requests with user-controlled URLs
SSRF_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.options",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib.request.urlretrieve",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "httpx.AsyncClient.get",
    "httpx.AsyncClient.post",
    "httpx.Client.get",
    "httpx.Client.post",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    # Instance method calls (session.get, client.post, etc.)
    "session.get",
    "session.post",
    "session.put",
    "session.delete",
    "session.request",
    "client.get",
    "client.post",
    # from-import aliases
    "urlopen",
}

# Path traversal sinks — file operations with user-controlled paths
# NOTE: os.path.join and pathlib.Path are path constructors, not sinks.
# They are tracked via taint propagation instead.
PATH_TRAVERSAL_SINKS = {
    "open",
    "shutil.copy",
    "shutil.copy2",
    "shutil.move",
    "shutil.rmtree",
    "shutil.make_archive",
    "shutil.unpack_archive",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.makedirs",
    "os.listdir",
    "os.mkdir",
    "os.symlink",
    "os.link",
    "os.chdir",
    "os.walk",
}

# XXE sinks — XML parsers that may allow external entities
XXE_SINKS = {
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.sax.parse",
    "xml.sax.parseString",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    # Common import aliases (import xml.etree.ElementTree as ET)
    "ET.parse",
    "ET.fromstring",
    "ET.iterparse",
    "etree.parse",
    "etree.fromstring",
    "minidom.parse",
    "minidom.parseString",
}

# Weak cryptography — hashes and ciphers that should not be used for security
WEAK_CRYPTO_FUNCTIONS = {
    "hashlib.md5",
    "hashlib.sha1",
    "Crypto.Cipher.DES.new",
    "Crypto.Cipher.ARC4.new",
    "Cryptodome.Cipher.DES.new",
    "Cryptodome.Cipher.ARC4.new",
    # from-import aliases
    "md5",   # from hashlib import md5
    "sha1",  # from hashlib import sha1
}

# Template injection sinks
TEMPLATE_INJECTION_SINKS = {
    "jinja2.Environment.from_string",
    "jinja2.Template",
    "mako.template.Template",
    "mako.lookup.TemplateLookup",
    "django.template.Template",
    "flask.render_template_string",
    # from-import aliases
    "Template",
    "render_template_string",
}

# Open redirect sinks
OPEN_REDIRECT_SINKS = {
    "flask.redirect",
    "redirect",
    "django.shortcuts.redirect",
    "HttpResponseRedirect",
    "werkzeug.utils.redirect",
}

# LDAP injection sinks
LDAP_INJECTION_SINKS = {
    "ldap.search_s",
    "ldap.search",
    "ldap.search_ext_s",
    "ldap3.Connection.search",
    # Instance method calls (conn.search_s, conn.search)
    "conn.search_s",
    "conn.search",
    "conn.search_ext_s",
    "connection.search",
}

# Sensitive data keywords
SENSITIVE_KEYWORDS = {
    "password",
    "passwd",
    "token",
    "secret",
    "key",
    "ssn",
    "credit_card",
    "api_key",
    "auth",
    "session",
    "cookie",
    "private",
    "credential",
}

# Taint analysis definitions
TAINT_SOURCES = {
    "input",
    "os.environ",
    "sys.argv",
    "request.args",
    "request.form",
    "request.get_json",
    "open",
    "read",
    "recv",
}
TAINT_SINKS = (
    DANGEROUS_FUNCTIONS
    | {"cursor.execute", "execute", "os.popen", "os.popen2", "os.popen3", "os.popen4"}
    | DESERIALIZATION_SINKS
    | SSRF_SINKS
    | PATH_TRAVERSAL_SINKS
    | XXE_SINKS
    | TEMPLATE_INJECTION_SINKS
    | LDAP_INJECTION_SINKS
)

# CodeBERT model for embeddings
CODEBERT_MODEL = "microsoft/codebert-base"
_tokenizer = None
_model = None


def get_git_churn_features(filepath):
    """
    Extract commit_count, unique_authors, last_modified_days for a file using git log.
    Returns a dict with these features, or zeros if not a git repo.
    """
    try:
        # Get commit count
        commit_count = int(
            subprocess.check_output(["git", "log", "--pretty=oneline", "--", filepath]).decode("utf-8").count("\n")
        )
        # Get unique authors
        authors = subprocess.check_output(["git", "log", "--format=%an", "--", filepath]).decode("utf-8").splitlines()
        unique_authors = len(set(authors))
        # Get last modified date
        last_date_str = (
            subprocess.check_output(["git", "log", "-1", "--format=%cd", "--date=iso", "--", filepath])
            .decode("utf-8")
            .strip()
        )
        last_date = datetime.datetime.fromisoformat(last_date_str[:19])
        days_since = (datetime.datetime.now() - last_date).days
        return {"commit_count": commit_count, "unique_authors": unique_authors, "last_modified_days": days_since}
    except Exception:
        return {"commit_count": 0, "unique_authors": 0, "last_modified_days": 0}


def detect_sensitive_vars(node):
    """
    Scan variable names and function arguments for sensitive keywords.
    Returns a set of sensitive variable names.
    """
    sensitive = set()
    for child in ast.walk(node):
        # Variable assignments
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()
                    if any(kw in name for kw in SENSITIVE_KEYWORDS):
                        sensitive.add(target.id)
        # Function arguments
        if isinstance(child, ast.FunctionDef):
            for arg in child.args.args:
                name = arg.arg.lower()
                if any(kw in name for kw in SENSITIVE_KEYWORDS):
                    sensitive.add(arg.arg)
    return sensitive


class FunctionAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.functions = []

    def visit_FunctionDef(self, node):
        sensitive_vars = detect_sensitive_vars(node)
        func_info = {
            "name": node.name,
            "lineno": node.lineno,
            "length": len(node.body),
            "dangerous_calls": [],
            "deserialization_calls": [],
            "ssrf_calls": [],
            "path_traversal_calls": [],
            "xxe_calls": [],
            "weak_crypto_calls": [],
            "template_injection_calls": [],
            "open_redirect_calls": [],
            "ldap_injection_calls": [],
            "cyclomatic_complexity": self._cyclomatic_complexity(node),
            "max_nesting_depth": self._max_nesting_depth(node),
            "input_validation": self._input_validation(node),
            "sensitive_data_involved": bool(sensitive_vars),
            "num_sensitive_vars": len(sensitive_vars),
        }
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child.func)
                if func_name in DANGEROUS_FUNCTIONS:
                    func_info["dangerous_calls"].append(func_name)
                if func_name in DESERIALIZATION_SINKS:
                    # yaml.load is safe if Loader=SafeLoader is used
                    if func_name == "yaml.load" and self._has_safe_loader(child):
                        pass
                    else:
                        func_info["deserialization_calls"].append(func_name)
                if func_name in SSRF_SINKS:
                    func_info["ssrf_calls"].append(func_name)
                if func_name in PATH_TRAVERSAL_SINKS:
                    func_info["path_traversal_calls"].append(func_name)
                if func_name in XXE_SINKS:
                    func_info["xxe_calls"].append(func_name)
                if func_name in WEAK_CRYPTO_FUNCTIONS:
                    func_info["weak_crypto_calls"].append(func_name)
                if func_name in TEMPLATE_INJECTION_SINKS:
                    func_info["template_injection_calls"].append(func_name)
                if func_name in OPEN_REDIRECT_SINKS:
                    func_info["open_redirect_calls"].append(func_name)
                if func_name in LDAP_INJECTION_SINKS:
                    func_info["ldap_injection_calls"].append(func_name)
        self.functions.append(func_info)
        self.generic_visit(node)

    @staticmethod
    def _has_safe_loader(call_node):
        """Check if a yaml.load() call uses Loader=SafeLoader or similar safe loaders.

        BaseLoader is included because it only resolves basic YAML tags and does
        not construct arbitrary Python objects, making it safe for untrusted input.
        """
        safe_loaders = {"SafeLoader", "CSafeLoader", "BaseLoader"}
        for kw in call_node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    if kw.value.attr in safe_loaders:
                        return True
                elif isinstance(kw.value, ast.Name):
                    if kw.value.id in safe_loaders:
                        return True
        return False

    def _get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""

    def _cyclomatic_complexity(self, node):
        # Simple cyclomatic complexity: 1 + number of branching points
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler, ast.With, ast.Try)):
                complexity += 1
        return complexity

    def _max_nesting_depth(self, node):
        def depth(n, current=0):
            if not hasattr(n, "body") or not isinstance(n.body, list):
                return current
            if not n.body:
                return current
            return max([depth(child, current + 1) for child in n.body] + [current])

        return depth(node)

    def _input_validation(self, node):
        found = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child.func)
                for mod in VALIDATION_MODULES:
                    if func_name.startswith(mod):
                        for vfunc in VALIDATION_FUNCTIONS:
                            if func_name.endswith(vfunc):
                                found.add(func_name)
        return list(found)


def get_code_embedding(code):
    global _tokenizer, _model
    if _tokenizer is None or _model is None:
        _tokenizer = AutoTokenizer.from_pretrained(CODEBERT_MODEL)
        _model = AutoModel.from_pretrained(CODEBERT_MODEL)
    inputs = _tokenizer(code, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        outputs = _model(**inputs)
        # Use [CLS] token embedding as representation
        embedding = outputs.last_hidden_state[:, 0, :].squeeze().numpy()
    return embedding.tolist()


def analyze_python_file(filepath):
    """
    Analyze a Python file for complexity and dangerous patterns.
    Returns a list of findings.
    """
    with open(filepath, "r") as f:
        source = f.read()
    tree = ast.parse(source, filename=filepath)
    analyzer = FunctionAnalyzer()
    analyzer.visit(tree)
    findings = []
    # Extended vulnerability categories to check
    _extended_vuln_keys = [
        "deserialization_calls",
        "ssrf_calls",
        "path_traversal_calls",
        "xxe_calls",
        "weak_crypto_calls",
        "template_injection_calls",
        "open_redirect_calls",
        "ldap_injection_calls",
    ]
    for func in analyzer.functions:
        has_extended_vulns = any(func.get(k) for k in _extended_vuln_keys)
        if func["dangerous_calls"] or has_extended_vulns or func["length"] > 50 or func["cyclomatic_complexity"] > 10:
            # Extract function source code
            func_code = None
            try:
                lines = source.splitlines()
                start = func["line"] - 1
                # Try to get the function block (up to next def/class or end)
                end = start + 1
                while end < len(lines) and not lines[end].lstrip().startswith(("def ", "class ")):
                    end += 1
                func_code = "\n".join(lines[start:end])
            except Exception:
                func_code = ""
            embedding = get_code_embedding(func_code) if func_code else []
            finding = {
                    "type": "function_analysis",
                    "function": func["name"],
                    "line": func["lineno"],
                    "length": func["length"],
                    "dangerous_calls": func["dangerous_calls"],
                    "deserialization_calls": func["deserialization_calls"],
                    "ssrf_calls": func["ssrf_calls"],
                    "path_traversal_calls": func["path_traversal_calls"],
                    "xxe_calls": func["xxe_calls"],
                    "weak_crypto_calls": func["weak_crypto_calls"],
                    "template_injection_calls": func["template_injection_calls"],
                    "open_redirect_calls": func["open_redirect_calls"],
                    "ldap_injection_calls": func["ldap_injection_calls"],
                    "cyclomatic_complexity": func["cyclomatic_complexity"],
                    "max_nesting_depth": func["max_nesting_depth"],
                    "input_validation": func["input_validation"],
                    "sensitive_data_involved": func["sensitive_data_involved"],
                    "num_sensitive_vars": func["num_sensitive_vars"],
                    "embedding": embedding,
                }
            findings.append(finding)
    return findings


def run_bandit(filepath):
    """
    Run bandit on the given file and return parsed results.
    """
    try:
        result = subprocess.run(["bandit", "-f", "json", "-q", filepath], capture_output=True, text=True, check=True)
        import json

        data = json.loads(result.stdout)
        issues = data.get("results", [])
        findings = []
        for issue in issues:
            findings.append(
                {
                    "type": "bandit",
                    "test_id": issue.get("test_id"),
                    "issue_text": issue.get("issue_text"),
                    "line_number": issue.get("line_number"),
                    "severity": issue.get("issue_severity"),
                    "confidence": issue.get("issue_confidence"),
                }
            )
        return findings
    except Exception as e:
        from .logging_config import get_logger

        _bandit_logger = get_logger(__name__)
        _bandit_logger.warning("Bandit analysis failed: %s", e)
        _bandit_logger.debug("Traceback:", exc_info=True)
        return []


def parse_requirement_line(line):
    # Parse lines like 'package==1.2.3' or 'package>=1.0.0'
    m = re.match(r"([a-zA-Z0-9_\-]+)([=<>!~]+([a-zA-Z0-9_.]+))?", line)
    if m:
        name = m.group(1)
        version = m.group(3) if m.group(3) else None
        return name, version
    return None, None


def check_pypi_latest_version(package):
    try:
        resp = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data["info"]["version"]
    except Exception:
        pass
    return None


def check_vulnerable_stub(package, version):
    """Legacy stub — kept for backward compatibility.  Use :func:`check_vulnerable` instead."""
    try:
        from .vuln_db import check_vulnerable

        is_vuln, details = check_vulnerable(package, version or "", ecosystem="PyPI")
        if is_vuln and details:
            return True, details.get("severity")
        return False, None
    except Exception as exc:  # noqa: BLE001
        logger.warning("OSV lookup failed for %s@%s: %s", package, version, exc)
        return False, None


def extract_python_dependencies(path):
    req_path = os.path.join(path, "requirements.txt")
    deps = []
    num_outdated = 0
    num_vuln = 0
    max_severity = None
    if os.path.exists(req_path):
        with open(req_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                name, version = parse_requirement_line(line)
                if name:
                    dep = {"name": name, "version": version}
                    # Outdated check
                    latest = check_pypi_latest_version(name)
                    if latest and version and latest != version:
                        dep["outdated"] = True
                        num_outdated += 1
                    else:
                        dep["outdated"] = False
                    # Vulnerability check (stub)
                    vuln, severity = check_vulnerable_stub(name, version)
                    dep["vulnerable"] = vuln
                    if vuln:
                        num_vuln += 1
                        if severity:
                            _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
                            if max_severity is None or _sev_order.get(severity, 99) < _sev_order.get(max_severity, 99):
                                max_severity = severity
                    deps.append(dep)
    return deps, num_vuln, num_outdated, max_severity


def taint_analysis(filepath):
    """
    Perform simple taint analysis: track untrusted sources to dangerous sinks.
    Returns a list of taint findings.
    """
    with open(filepath, "r") as f:
        source = f.read()
    tree = ast.parse(source, filename=filepath)
    tainted_vars = set()
    findings = []
    traces = {}

    class TaintVisitor(ast.NodeVisitor):
        def visit_Assign(self, node):
            # Check if value is a taint source
            if isinstance(node.value, ast.Call):
                func_name = FunctionAnalyzer()._get_func_name(node.value.func)
                if func_name in TAINT_SOURCES:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars.add(target.id)
                            traces[target.id] = [(node.lineno, func_name)]
            self.generic_visit(node)

        def visit_Call(self, node):
            func_name = FunctionAnalyzer()._get_func_name(node.func)
            # If any arg is tainted and this is a sink, flag it
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in tainted_vars and func_name in TAINT_SINKS:
                    findings.append(
                        {
                            "type": "taint_analysis",
                            "source": traces.get(arg.id, []),
                            "sink": func_name,
                            "sink_line": node.lineno,
                            "variable": arg.id,
                            "trace": traces.get(arg.id, []) + [(node.lineno, func_name)],
                        }
                    )
            self.generic_visit(node)

        def visit_Name(self, node):
            # Propagate taint through assignments
            pass

    TaintVisitor().visit(tree)
    return findings


def analyze_python_project(path):
    """
    Recursively analyze all .py files in a directory.
    Returns a list of findings, including a dependencies finding if requirements.txt is present.
    """
    findings = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                fpath = os.path.join(root, file)
                churn = get_git_churn_features(fpath)
                for finding in analyze_python_file(fpath):
                    finding.update(churn)
                    findings.append(finding)
                for finding in run_bandit(fpath):
                    finding.update(churn)
                    findings.append(finding)
                for finding in taint_analysis(fpath):
                    finding.update(churn)
                    findings.append(finding)
    deps, num_vuln, num_outdated, max_severity = extract_python_dependencies(path)
    if deps:
        findings.append(
            {
                "type": "dependencies",
                "dependencies": deps,
                "num_vulnerable_dependencies": num_vuln,
                "num_outdated_dependencies": num_outdated,
                "max_dependency_severity": max_severity,
            }
        )
    return findings
