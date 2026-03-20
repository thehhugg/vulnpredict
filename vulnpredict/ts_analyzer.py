"""TypeScript and TSX analyzer.

Extends the JavaScript security analysis to TypeScript (.ts) and TSX (.tsx)
files. Uses regex-based pattern detection (same as js_security_patterns) plus
TypeScript-specific patterns for type safety issues.

TypeScript-specific detections:
- Excessive ``any`` type usage
- Type assertion bypasses (``as any``, ``as unknown``)
- Non-null assertion abuse (``!.``)
- ``@ts-ignore`` / ``@ts-expect-error`` suppression comments
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from .js_security_patterns import scan_js_file_patterns

# ---------------------------------------------------------------------------
# TypeScript-specific patterns
# ---------------------------------------------------------------------------

# Excessive `any` type annotations
_ANY_TYPE_PATTERNS = [
    re.compile(r""":\s*any\b"""),
    re.compile(r"""<any>"""),
    re.compile(r"""as\s+any\b"""),
]

# Type assertion bypasses
_TYPE_ASSERTION_BYPASS = [
    re.compile(r"""as\s+any\b"""),
    re.compile(r"""as\s+unknown\b"""),
    re.compile(r"""<any>\s*\("""),
]

# Non-null assertion abuse (variable!.property)
_NON_NULL_ASSERTION = re.compile(r"""\w+!\.\w+""")

# TypeScript suppression comments
_TS_SUPPRESSION = [
    re.compile(r"""//\s*@ts-ignore\b"""),
    re.compile(r"""//\s*@ts-expect-error\b"""),
]


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def detect_any_type_abuse(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect excessive use of the ``any`` type."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _ANY_TYPE_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "any_type_abuse",
                    "rule_id": "VP-TS-001",
                    "name": "Excessive any Type",
                    "file": filename,
                    "line": i,
                    "severity": "low",
                    "cwe": "CWE-1007",
                    "message": "Use of 'any' type weakens type safety; consider using a specific type",
                })
                break
    return findings


def detect_type_assertion_bypass(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect type assertion bypasses (``as any``, ``as unknown``)."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _TYPE_ASSERTION_BYPASS:
            if pattern.search(line):
                findings.append({
                    "type": "type_assertion_bypass",
                    "rule_id": "VP-TS-002",
                    "name": "Type Assertion Bypass",
                    "file": filename,
                    "line": i,
                    "severity": "medium",
                    "cwe": "CWE-1007",
                    "message": "Type assertion bypass detected; this circumvents TypeScript's type checking",
                })
                break
    return findings


def detect_non_null_assertion(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect non-null assertion operator abuse."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if _NON_NULL_ASSERTION.search(line):
            findings.append({
                "type": "non_null_assertion",
                "rule_id": "VP-TS-003",
                "name": "Non-null Assertion",
                "file": filename,
                "line": i,
                "severity": "low",
                "cwe": "CWE-476",
                "message": "Non-null assertion operator (!) used; may cause runtime null errors",
            })
    return findings


def detect_ts_suppression_comments(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect @ts-ignore and @ts-expect-error comments."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        for pattern in _TS_SUPPRESSION:
            if pattern.search(line):
                findings.append({
                    "type": "ts_suppression",
                    "rule_id": "VP-TS-004",
                    "name": "TypeScript Error Suppression",
                    "file": filename,
                    "line": i,
                    "severity": "low",
                    "cwe": "CWE-1007",
                    "message": "TypeScript error suppression comment detected; may hide type errors",
                })
                break
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_ts_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a TypeScript/TSX file for security and type safety issues.

    Applies both the standard JS security patterns and TypeScript-specific
    detections.

    Args:
        filepath: Path to the .ts or .tsx file.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    # Apply JS security patterns (prototype pollution, ReDoS, etc.)
    findings.extend(scan_js_file_patterns(filepath))

    # Apply TypeScript-specific patterns
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    findings.extend(detect_any_type_abuse(lines, filepath))
    findings.extend(detect_type_assertion_bypass(lines, filepath))
    findings.extend(detect_non_null_assertion(lines, filepath))
    findings.extend(detect_ts_suppression_comments(lines, filepath))

    return findings


def scan_ts_directory(directory: str) -> List[Dict[str, Any]]:
    """Scan a directory recursively for TypeScript/TSX security issues.

    Args:
        directory: Path to the directory.

    Returns:
        List of finding dicts.
    """
    skip_dirs = {"node_modules", ".git", "__pycache__", "dist", "build", ".next"}
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if fname.endswith((".ts", ".tsx")):
                fpath = os.path.join(root, fname)
                findings.extend(scan_ts_file(fpath))

    return findings
