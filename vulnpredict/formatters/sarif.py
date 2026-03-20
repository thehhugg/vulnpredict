"""SARIF v2.1.0 output formatter for VulnPredict scan results.

Produces a valid SARIF (Static Analysis Results Interchange Format) log
conforming to the OASIS SARIF v2.1.0 specification. The output is compatible
with GitHub Code Scanning, GitLab SAST, Azure DevOps, and other SARIF consumers.

References:
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import os
from typing import Any, Dict, List, Optional

# Version is read from pyproject.toml at import time; fallback to "dev"
try:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

    _pyproject = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
    if os.path.isfile(_pyproject):
        with open(_pyproject, "rb") as _f:
            _VERSION = tomllib.load(_f).get("project", {}).get("version", "dev")
    else:
        _VERSION = "dev"
except Exception:
    _VERSION = "dev"

# SARIF schema URI
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Information URI for VulnPredict
TOOL_INFO_URI = "https://github.com/thehhugg/vulnpredict"

# Rule definitions for each finding type
RULES: Dict[str, Dict[str, Any]] = {
    "VP001": {
        "id": "VP001",
        "name": "TaintedDataFlow",
        "shortDescription": {"text": "Tainted data flows from source to dangerous sink"},
        "fullDescription": {
            "text": "A variable assigned from an untrusted source (e.g., input(), "
            "request.args) flows to a dangerous sink (e.g., eval(), exec(), "
            "cursor.execute()) without sanitization."
        },
        "helpUri": f"{TOOL_INFO_URI}#taint-analysis",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "taint-analysis", "CWE-20"]},
    },
    "VP002": {
        "id": "VP002",
        "name": "InterproceduralTaintFlow",
        "shortDescription": {"text": "Tainted data flows across function boundaries to a dangerous sink"},
        "fullDescription": {
            "text": "An interprocedural taint analysis detected that untrusted data "
            "crosses function call boundaries and reaches a dangerous sink."
        },
        "helpUri": f"{TOOL_INFO_URI}#interprocedural-taint",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "taint-analysis", "interprocedural", "CWE-20"]},
    },
    "VP003": {
        "id": "VP003",
        "name": "DangerousFunction",
        "shortDescription": {"text": "Use of dangerous function"},
        "fullDescription": {
            "text": "A dangerous function (e.g., eval, exec, os.system) was called. "
            "These functions can lead to code injection if used with untrusted input."
        },
        "helpUri": f"{TOOL_INFO_URI}#dangerous-functions",
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "dangerous-function", "CWE-78"]},
    },
    "VP004": {
        "id": "VP004",
        "name": "HardcodedSecret",
        "shortDescription": {"text": "Hardcoded secret or credential detected"},
        "fullDescription": {
            "text": "A variable name suggests it contains a secret (e.g., password, "
            "API key, token) and is assigned a hardcoded string literal."
        },
        "helpUri": f"{TOOL_INFO_URI}#hardcoded-secrets",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "secrets", "CWE-798"]},
    },
    "VP005": {
        "id": "VP005",
        "name": "HighComplexity",
        "shortDescription": {"text": "Function has high cyclomatic complexity"},
        "fullDescription": {
            "text": "A function exceeds the cyclomatic complexity threshold, making "
            "it harder to test, maintain, and reason about for security."
        },
        "helpUri": f"{TOOL_INFO_URI}#complexity",
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["maintainability", "complexity"]},
    },
    "VP006": {
        "id": "VP006",
        "name": "JavaScriptVulnerability",
        "shortDescription": {"text": "JavaScript security vulnerability detected"},
        "fullDescription": {
            "text": "A JavaScript-specific vulnerability pattern was detected, such as "
            "eval() usage, DOM XSS, or use of dangerous APIs."
        },
        "helpUri": f"{TOOL_INFO_URI}#javascript-analysis",
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "javascript"]},
    },
}


def _get_rule_id(finding: Dict[str, Any]) -> str:
    """Map a finding type to a SARIF rule ID."""
    ftype = finding.get("type", "")
    mapping = {
        "taint_analysis": "VP001",
        "interprocedural_taint": "VP002",
        "dangerous_function": "VP003",
        "hardcoded_secret": "VP004",
        "high_complexity": "VP005",
        "js_vulnerability": "VP006",
        "dangerous_js_function": "VP006",
    }
    return mapping.get(ftype, "VP003")


def _get_level(finding: Dict[str, Any]) -> str:
    """Map a finding to a SARIF level (error, warning, note)."""
    score = finding.get("vuln_score")
    if score is not None:
        if score >= 0.8:
            return "error"
        if score >= 0.5:
            return "warning"
        return "note"

    ftype = finding.get("type", "")
    if ftype in ("taint_analysis", "interprocedural_taint", "hardcoded_secret"):
        return "error"
    if ftype == "high_complexity":
        return "note"
    return "warning"


def _get_message(finding: Dict[str, Any]) -> str:
    """Build a human-readable message for a finding."""
    ftype = finding.get("type", "")

    if ftype == "taint_analysis":
        var = finding.get("variable", "unknown")
        sink = finding.get("sink", "unknown")
        return f"Tainted variable '{var}' flows to dangerous sink '{sink}'"

    if ftype == "interprocedural_taint":
        var = finding.get("tainted_var", "unknown")
        sink = finding.get("sink", "unknown")
        chain = " -> ".join(finding.get("call_chain", []))
        return f"Interprocedural taint: '{var}' reaches '{sink}' via {chain}"

    if ftype == "dangerous_function":
        func = finding.get("function", "unknown")
        return f"Dangerous function call: {func}"

    if ftype == "hardcoded_secret":
        var = finding.get("variable", "unknown")
        return f"Hardcoded secret detected in variable '{var}'"

    if ftype == "high_complexity":
        complexity = finding.get("complexity", "?")
        return f"High cyclomatic complexity: {complexity}"

    return finding.get("message", str(finding))


def _get_location(finding: Dict[str, Any], scan_path: str) -> Dict[str, Any]:
    """Build a SARIF location object from a finding."""
    filepath = finding.get("file", finding.get("filename", "unknown"))

    # Make path relative to scan_path if it's absolute
    if os.path.isabs(filepath) and scan_path:
        try:
            filepath = os.path.relpath(filepath, scan_path)
        except ValueError:
            pass

    line = finding.get("line", finding.get("sink_line", 1))
    if not isinstance(line, int) or line < 1:
        line = 1

    location = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": filepath,
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": line,
                "startColumn": 1,
            },
        }
    }

    # Try to add code snippet context
    snippet = _get_code_snippet(finding, scan_path, filepath, line)
    if snippet:
        location["physicalLocation"]["region"]["snippet"] = {"text": snippet["line"]}
        if "context" in snippet:
            location["physicalLocation"]["contextRegion"] = {
                "startLine": max(1, line - 2),
                "endLine": line + 2,
                "snippet": {"text": snippet["context"]},
            }

    return location


def _get_code_snippet(
    finding: Dict[str, Any],
    scan_path: str,
    filepath: str,
    line: int,
) -> Optional[Dict[str, str]]:
    """Try to read the source code snippet for a finding."""
    # Try to resolve the actual file path
    candidates = [
        os.path.join(scan_path, filepath) if scan_path else filepath,
        filepath,
    ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", errors="replace") as f:
                    lines = f.readlines()
                if 1 <= line <= len(lines):
                    target_line = lines[line - 1].rstrip("\n")
                    # Context: 2 lines before and after
                    start = max(0, line - 3)
                    end = min(len(lines), line + 2)
                    context = "".join(lines[start:end])
                    return {"line": target_line, "context": context}
            except (OSError, UnicodeDecodeError):
                pass
    return None


def _finding_to_result(
    finding: Dict[str, Any],
    index: int,
    scan_path: str,
    rule_index_map: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Convert a VulnPredict finding to a SARIF result object."""
    rule_id = _get_rule_id(finding)

    # Use the provided rule_index_map if available, otherwise compute from RULES
    if rule_index_map and rule_id in rule_index_map:
        rule_index = rule_index_map[rule_id]
    else:
        rule_index = list(RULES.keys()).index(rule_id) if rule_id in RULES else 0

    result = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _get_level(finding),
        "message": {"text": _get_message(finding)},
        "locations": [_get_location(finding, scan_path)],
    }

    # Add fingerprint for deduplication
    fp_parts = [
        rule_id,
        finding.get("file", finding.get("filename", "")),
        str(finding.get("line", finding.get("sink_line", ""))),
        finding.get("variable", finding.get("tainted_var", finding.get("function", ""))),
    ]
    result["fingerprints"] = {
        "vulnpredict/v1": "/".join(str(p) for p in fp_parts),
    }

    # Add properties with extra metadata
    props = {}
    if "vuln_score" in finding:
        props["confidence"] = finding["vuln_score"]
    if "trace" in finding:
        props["trace"] = finding["trace"]
    if "call_chain" in finding:
        props["callChain"] = finding["call_chain"]
    if props:
        result["properties"] = props

    return result


def format_sarif(
    findings: List[Dict[str, Any]],
    scan_path: str,
) -> str:
    """Format scan findings as a SARIF v2.1.0 JSON string.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.

    Returns:
        Pretty-printed SARIF JSON string.
    """
    # First pass: collect which rules are used
    used_rule_ids = set()
    for finding in findings:
        used_rule_ids.add(_get_rule_id(finding))

    # Build rules array (only include rules that have findings)
    rules = [RULES[rid] for rid in RULES if rid in used_rule_ids]

    # Build rule_index_map from the filtered rules array
    rule_index_map = {r["id"]: idx for idx, r in enumerate(rules)}

    # Second pass: generate results with correct ruleIndex
    results = []
    for i, finding in enumerate(findings):
        result = _finding_to_result(finding, i, scan_path, rule_index_map)
        results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnPredict",
                        "version": _VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)


def write_sarif(
    findings: List[Dict[str, Any]],
    scan_path: str,
    output_path: str,
) -> None:
    """Format and write scan findings to a SARIF file.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.
        output_path: Path to write the SARIF output file.
    """
    sarif_str = format_sarif(findings, scan_path)
    with open(output_path, "w") as f:
        f.write(sarif_str)
        f.write("\n")
