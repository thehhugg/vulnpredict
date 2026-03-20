"""Go security analyzer for VulnPredict.

Detects common vulnerability patterns in Go source files using
regex-based pattern matching. Covers:

- SQL injection via string concatenation in database queries
- Command injection via os/exec with unsanitized input
- Path traversal via filepath.Join with user input
- Weak cryptography (DES, RC4, MD5 for security)
- Hardcoded credentials
- Insecure TLS configuration (InsecureSkipVerify)
- Race conditions (shared state without mutex)
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

_GO_RULES: List[Dict[str, Any]] = [
    # --- SQL injection ---
    {
        "rule_id": "VP-GO-001",
        "name": "SQL Injection via String Concatenation",
        "pattern": re.compile(
            r'(?:'
            # Pattern 1: db.Query("..." + var)
            r'(?:db|tx|conn|rows?)\.\ s*(?:Query|Exec|QueryRow|Prepare)\s*\([^)]*(?:\+|fmt\.Sprintf)'
            r'|'
            # Pattern 2: query built with string concat then passed to db.Query
            r'(?:query|sql|stmt|q)\s*(?::=|=|\+=)\s*(?:"[^"]*"\s*\+|fmt\.Sprintf\s*\(\s*"[^"]*%[svdq])'
            r')',
            re.MULTILINE | re.IGNORECASE,
        ),
        "severity": "critical",
        "cwe": "CWE-89",
        "message": "Potential SQL injection: query built with string concatenation or fmt.Sprintf",
    },
    # --- Command injection ---
    {
        "rule_id": "VP-GO-002",
        "name": "Command Injection via os/exec",
        "pattern": re.compile(
            r'exec\.Command\s*\(\s*(?:[^")\s]|fmt\.Sprintf|"[^"]*"\s*\+)',
            re.MULTILINE,
        ),
        "severity": "critical",
        "cwe": "CWE-78",
        "message": "Potential command injection: exec.Command with dynamic argument",
    },
    {
        "rule_id": "VP-GO-003",
        "name": "Command Injection via os.system equivalent",
        "pattern": re.compile(
            r'exec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"-c"',
        ),
        "severity": "critical",
        "cwe": "CWE-78",
        "message": "Shell command execution via exec.Command with sh/bash -c",
    },
    # --- Path traversal ---
    {
        "rule_id": "VP-GO-004",
        "name": "Path Traversal Risk",
        "pattern": re.compile(
            r'filepath\.Join\s*\([^)]*(?:r\.(?:URL|Form|Query)|'
            r'c\.(?:Param|Query)|params|userInput|req\.|input)',
            re.MULTILINE,
        ),
        "severity": "high",
        "cwe": "CWE-22",
        "message": "Potential path traversal: filepath.Join with user-controlled input",
    },
    # --- Weak cryptography ---
    {
        "rule_id": "VP-GO-005",
        "name": "Weak Cryptography - DES",
        "pattern": re.compile(r'"crypto/des"'),
        "severity": "high",
        "cwe": "CWE-327",
        "message": "Use of weak DES encryption algorithm; prefer AES-256",
    },
    {
        "rule_id": "VP-GO-006",
        "name": "Weak Cryptography - RC4",
        "pattern": re.compile(r'"crypto/rc4"'),
        "severity": "high",
        "cwe": "CWE-327",
        "message": "Use of weak RC4 cipher; prefer AES-GCM or ChaCha20",
    },
    {
        "rule_id": "VP-GO-007",
        "name": "Weak Hash - MD5 for Security",
        "pattern": re.compile(r'md5\.(?:New|Sum)\b'),
        "severity": "medium",
        "cwe": "CWE-328",
        "message": "MD5 used for hashing; not suitable for security purposes, use SHA-256+",
    },
    {
        "rule_id": "VP-GO-008",
        "name": "Weak Hash - SHA1 for Security",
        "pattern": re.compile(r'sha1\.(?:New|Sum)\b'),
        "severity": "medium",
        "cwe": "CWE-328",
        "message": "SHA1 used for hashing; considered weak, use SHA-256+",
    },
    # --- Hardcoded credentials ---
    {
        "rule_id": "VP-GO-009",
        "name": "Hardcoded Password",
        "pattern": re.compile(
            r'(?:password|passwd|secret|apiKey|api_key|token)\s*'
            r'(?::=|=)\s*"[^"]{8,}"',
            re.IGNORECASE,
        ),
        "severity": "high",
        "cwe": "CWE-798",
        "message": "Hardcoded credential or secret detected in source code",
    },
    # --- Insecure TLS ---
    {
        "rule_id": "VP-GO-010",
        "name": "Insecure TLS - Skip Verification",
        "pattern": re.compile(r'InsecureSkipVerify\s*:\s*true'),
        "severity": "high",
        "cwe": "CWE-295",
        "message": "TLS certificate verification disabled (InsecureSkipVerify: true)",
    },
    {
        "rule_id": "VP-GO-011",
        "name": "Insecure TLS - Minimum Version",
        "pattern": re.compile(
            r'MinVersion\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b'
        ),
        "severity": "medium",
        "cwe": "CWE-326",
        "message": "Insecure minimum TLS version; use tls.VersionTLS12 or higher",
    },
    # --- Race conditions ---
    {
        "rule_id": "VP-GO-012",
        "name": "Potential Race Condition",
        "pattern": re.compile(
            r'go\s+func\s*\([^)]*\)\s*\{[^}]*(?:map\[|'
            r'(?:=\s*append|[a-z]+\s*(?:\+\+|--|\+=|-=)))',
            re.DOTALL,
        ),
        "severity": "medium",
        "cwe": "CWE-362",
        "message": "Potential race condition: goroutine modifying shared state without synchronization",
    },
    # --- Unsafe pointer ---
    {
        "rule_id": "VP-GO-013",
        "name": "Unsafe Pointer Usage",
        "pattern": re.compile(r'"unsafe"'),
        "severity": "medium",
        "cwe": "CWE-787",
        "message": "Import of 'unsafe' package; may lead to memory safety issues",
    },
    # --- Unhandled errors ---
    {
        "rule_id": "VP-GO-014",
        "name": "Ignored Error Return",
        "pattern": re.compile(
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*_\s*(?::=|=)\s*'
            r'(?:os|io|ioutil|http|sql|net|bufio|json|xml|csv)\.',
            re.MULTILINE,
        ),
        "severity": "low",
        "cwe": "CWE-391",
        "message": "Error return value explicitly ignored; may mask failures",
    },
    # --- HTTP without timeout ---
    {
        "rule_id": "VP-GO-015",
        "name": "HTTP Client Without Timeout",
        "pattern": re.compile(r'http\.(?:Get|Post|Head|PostForm)\s*\('),
        "severity": "medium",
        "cwe": "CWE-400",
        "message": "Default HTTP client used without timeout; may cause resource exhaustion",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_go_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a single Go source file for security vulnerabilities.

    Args:
        filepath: Path to the .go file.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.split("\n")

    for rule in _GO_RULES:
        for match in rule["pattern"].finditer(content):
            # Calculate line number from match position
            line_num = content[: match.start()].count("\n") + 1
            findings.append({
                "type": "go_vulnerability",
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "file": filepath,
                "line": line_num,
                "severity": rule["severity"],
                "cwe": rule["cwe"],
                "message": rule["message"],
                "match": match.group(0)[:120],
            })

    return findings


def scan_go_directory(directory: str) -> List[Dict[str, Any]]:
    """Scan a directory recursively for Go security vulnerabilities.

    Args:
        directory: Root directory to scan.

    Returns:
        List of finding dicts from all .go files.
    """
    skip_dirs = {
        ".git", "__pycache__", "node_modules", "vendor",
        "dist", "build", ".terraform", "testdata",
    }
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if fname.endswith(".go") and not fname.endswith("_test.go"):
                fpath = os.path.join(root, fname)
                findings.extend(scan_go_file(fpath))

    return findings
