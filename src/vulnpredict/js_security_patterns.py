"""Extended JavaScript security pattern detection.

Detects additional vulnerability classes in JavaScript source code using
regex-based pattern matching. This module supplements the AST-based
analysis in js_analyzer.py with patterns that are easier to detect via
regex than AST traversal.

Detected patterns:
- Prototype pollution
- ReDoS (Regular Expression Denial of Service)
- Open redirect
- Insecure randomness
- NoSQL injection
- Insecure postMessage
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Prototype pollution: assignment to __proto__ or constructor.prototype
_PROTO_POLLUTION_PATTERNS = [
    re.compile(r"""(\w+)\s*\[\s*['"]__proto__['"]\s*\]"""),
    re.compile(r"""(\w+)\.__proto__\s*="""),
    re.compile(r"""(\w+)\.constructor\.prototype\s*="""),
    re.compile(r"""Object\.assign\s*\(\s*\w+\.prototype"""),
]

# ReDoS: catastrophic backtracking patterns in regexes
# Detect nested quantifiers like (a+)+, (a*)*,  (a+|b)+ etc.
_REDOS_PATTERNS = [
    re.compile(r"""new\s+RegExp\s*\(\s*['"].*?([+*])\s*\).*?\1"""),
    re.compile(r"""/.*?(\([^)]*[+*][^)]*\))[+*].*?/"""),
    re.compile(r"""/.*?([+*])\s*\)\s*[+*].*?/"""),
]

# Open redirect: user-controlled input flowing to redirect
_OPEN_REDIRECT_PATTERNS = [
    re.compile(r"""window\.location\s*=\s*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""window\.location\.href\s*=\s*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""res\.redirect\s*\(\s*(?:req\.|request\.)"""),
    re.compile(r"""location\.replace\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""window\.location\s*=\s*(?:document\.URL|document\.referrer|location\.hash)"""),
    re.compile(r"""res\.redirect\s*\(\s*(?:url|redirect_url|next|return_to|callback)"""),
]

# Insecure randomness: Math.random() in security contexts
_INSECURE_RANDOM_PATTERNS = [
    re.compile(r"""(?:token|secret|key|password|nonce|csrf|session|salt)\s*=.*?Math\.random\s*\(\s*\)""", re.IGNORECASE),
    re.compile(r"""Math\.random\s*\(\s*\).*?(?:toString\s*\(\s*36\s*\))"""),
]

# NoSQL injection: unsanitized input in MongoDB queries
_NOSQL_INJECTION_PATTERNS = [
    re.compile(r"""\.find\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""\.findOne\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""\.update\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""\.deleteOne\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)"""),
    re.compile(r"""\$where\s*:"""),
]

# Insecure postMessage: missing origin check
_POSTMESSAGE_PATTERNS = [
    re.compile(r"""addEventListener\s*\(\s*['"]message['"]"""),
]

# Patterns for origin check in postMessage handler
_ORIGIN_CHECK_PATTERNS = [
    re.compile(r"""event\.origin"""),
    re.compile(r"""e\.origin"""),
    re.compile(r"""msg\.origin"""),
    re.compile(r"""message\.origin"""),
]


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def detect_prototype_pollution(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect prototype pollution patterns."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _PROTO_POLLUTION_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "prototype_pollution",
                    "rule_id": "VP-JS-001",
                    "name": "Prototype Pollution",
                    "file": filename,
                    "line": i,
                    "severity": "high",
                    "cwe": "CWE-1321",
                    "message": "Potential prototype pollution: direct modification of object prototype",
                })
                break
    return findings


def detect_redos(lines: List[str], filename: str) -> List[Dict[str, Any]]:
    """Detect ReDoS (Regular Expression Denial of Service) patterns."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _REDOS_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "redos",
                    "rule_id": "VP-JS-002",
                    "name": "ReDoS Vulnerability",
                    "file": filename,
                    "line": i,
                    "severity": "medium",
                    "cwe": "CWE-1333",
                    "message": "Potential ReDoS: regex with catastrophic backtracking pattern",
                })
                break
    return findings


def detect_open_redirect(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect open redirect patterns."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _OPEN_REDIRECT_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "open_redirect",
                    "rule_id": "VP-JS-003",
                    "name": "Open Redirect",
                    "file": filename,
                    "line": i,
                    "severity": "medium",
                    "cwe": "CWE-601",
                    "message": "Potential open redirect: user-controlled input used in redirect",
                })
                break
    return findings


def detect_insecure_randomness(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect insecure randomness in security-sensitive contexts."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _INSECURE_RANDOM_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "insecure_randomness",
                    "rule_id": "VP-JS-004",
                    "name": "Insecure Randomness",
                    "file": filename,
                    "line": i,
                    "severity": "medium",
                    "cwe": "CWE-330",
                    "message": "Math.random() used in security-sensitive context; use crypto.randomBytes() instead",
                })
                break
    return findings


def detect_nosql_injection(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect NoSQL injection patterns."""
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pattern in _NOSQL_INJECTION_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "nosql_injection",
                    "rule_id": "VP-JS-005",
                    "name": "NoSQL Injection",
                    "file": filename,
                    "line": i,
                    "severity": "high",
                    "cwe": "CWE-943",
                    "message": "Potential NoSQL injection: unsanitized user input in database query",
                })
                break
    return findings


def detect_insecure_postmessage(
    lines: List[str], filename: str
) -> List[Dict[str, Any]]:
    """Detect insecure postMessage handlers without origin checks."""
    findings: List[Dict[str, Any]] = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Check if this line adds a message event listener
        is_message_listener = False
        for pattern in _POSTMESSAGE_PATTERNS:
            if pattern.search(line):
                is_message_listener = True
                break

        if not is_message_listener:
            continue

        # Look ahead for origin check within the next 20 lines
        has_origin_check = False
        end = min(i + 20, len(lines))
        for j in range(i, end):
            for origin_pattern in _ORIGIN_CHECK_PATTERNS:
                if origin_pattern.search(lines[j]):
                    has_origin_check = True
                    break
            if has_origin_check:
                break

        if not has_origin_check:
            findings.append({
                "type": "insecure_postmessage",
                "rule_id": "VP-JS-006",
                "name": "Insecure postMessage Handler",
                "file": filename,
                "line": i,
                "severity": "medium",
                "cwe": "CWE-346",
                "message": "postMessage handler without origin validation; verify event.origin before processing",
            })

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_js_file_patterns(filepath: str) -> List[Dict[str, Any]]:
    """Scan a JavaScript file for security patterns.

    Args:
        filepath: Path to the JavaScript file.

    Returns:
        List of finding dicts.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    findings: List[Dict[str, Any]] = []
    findings.extend(detect_prototype_pollution(lines, filepath))
    findings.extend(detect_redos(lines, filepath))
    findings.extend(detect_open_redirect(lines, filepath))
    findings.extend(detect_insecure_randomness(lines, filepath))
    findings.extend(detect_nosql_injection(lines, filepath))
    findings.extend(detect_insecure_postmessage(lines, filepath))

    return findings


def scan_js_directory_patterns(directory: str) -> List[Dict[str, Any]]:
    """Scan a directory recursively for JavaScript security patterns.

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
            if fname.endswith((".js", ".jsx", ".mjs", ".ts", ".tsx")):
                fpath = os.path.join(root, fname)
                findings.extend(scan_js_file_patterns(fpath))

    return findings
