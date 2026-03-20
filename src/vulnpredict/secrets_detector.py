"""Comprehensive sensitive data and secrets detection.

Detects hardcoded secrets, tokens, API keys, private keys, and other
sensitive data in source code using a combination of regex patterns and
Shannon entropy analysis.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Secret pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    """A pattern for detecting a specific type of secret."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str = "high"
    cwe: str = "CWE-798"
    description: str = ""
    # Minimum match length to reduce false positives
    min_length: int = 8


# Pre-compiled patterns with low false-positive rates.
# Each pattern is designed to match the specific format of the secret type.
_PATTERNS: List[SecretPattern] = [
    # --- Cloud provider keys ---
    SecretPattern(
        id="VP-SEC-001",
        name="AWS Access Key ID",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>AKIA[0-9A-Z]{16})(?:['";\s]|$)"""),
        severity="critical",
        description="AWS access key ID detected. Rotate immediately.",
    ),
    SecretPattern(
        id="VP-SEC-002",
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"""(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*['"]?(?P<secret>[A-Za-z0-9/+=]{40})['"]?"""
        ),
        severity="critical",
        description="AWS secret access key detected. Rotate immediately.",
    ),
    # --- GitHub tokens ---
    SecretPattern(
        id="VP-SEC-003",
        name="GitHub Personal Access Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>ghp_[A-Za-z0-9]{36,})(?:['";\s]|$)"""),
        severity="critical",
        description="GitHub personal access token detected.",
    ),
    SecretPattern(
        id="VP-SEC-004",
        name="GitHub OAuth Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>gho_[A-Za-z0-9]{36,})(?:['";\s]|$)"""),
        severity="critical",
        description="GitHub OAuth token detected.",
    ),
    SecretPattern(
        id="VP-SEC-005",
        name="GitHub App Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>ghs_[A-Za-z0-9]{36,})(?:['";\s]|$)"""),
        severity="critical",
        description="GitHub App installation token detected.",
    ),
    SecretPattern(
        id="VP-SEC-006",
        name="GitHub Fine-Grained Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>github_pat_[A-Za-z0-9_]{36,})(?:['";\s]|$)"""),
        severity="critical",
        description="GitHub fine-grained personal access token detected.",
    ),
    # --- Slack tokens ---
    SecretPattern(
        id="VP-SEC-007",
        name="Slack Bot Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>xoxb-[0-9]{10,}-[0-9A-Za-z-]+)(?:['";\s]|$)"""),
        severity="high",
        description="Slack bot token detected.",
    ),
    SecretPattern(
        id="VP-SEC-008",
        name="Slack User Token",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>xoxp-[0-9]{10,}-[0-9A-Za-z-]+)(?:['";\s]|$)"""),
        severity="high",
        description="Slack user token detected.",
    ),
    SecretPattern(
        id="VP-SEC-009",
        name="Slack Webhook URL",
        pattern=re.compile(
            r"""(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"""
        ),
        severity="high",
        description="Slack webhook URL detected.",
    ),
    # --- Google ---
    SecretPattern(
        id="VP-SEC-010",
        name="Google API Key",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>AIza[0-9A-Za-z\-_]{35})(?:['";\s]|$)"""),
        severity="high",
        description="Google API key detected.",
    ),
    SecretPattern(
        id="VP-SEC-011",
        name="Google OAuth Client Secret",
        pattern=re.compile(
            r"""client_secret['":\s]+(?P<secret>GOCSPX-[A-Za-z0-9_-]{28,})"""
        ),
        severity="high",
        description="Google OAuth client secret detected.",
    ),
    # --- JWT ---
    SecretPattern(
        id="VP-SEC-012",
        name="JSON Web Token",
        pattern=re.compile(
            r"""(?:^|['"=\s:])(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"""
        ),
        severity="medium",
        description="JWT token detected. May contain sensitive claims.",
    ),
    # --- Private keys ---
    SecretPattern(
        id="VP-SEC-013",
        name="RSA Private Key",
        pattern=re.compile(r"""(?P<secret>-----BEGIN RSA PRIVATE KEY-----)"""),
        severity="critical",
        description="RSA private key detected.",
        min_length=5,
    ),
    SecretPattern(
        id="VP-SEC-014",
        name="SSH Private Key",
        pattern=re.compile(r"""(?P<secret>-----BEGIN OPENSSH PRIVATE KEY-----)"""),
        severity="critical",
        description="SSH private key detected.",
        min_length=5,
    ),
    SecretPattern(
        id="VP-SEC-015",
        name="PGP Private Key",
        pattern=re.compile(r"""(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)"""),
        severity="critical",
        description="PGP private key block detected.",
        min_length=5,
    ),
    SecretPattern(
        id="VP-SEC-016",
        name="Generic Private Key",
        pattern=re.compile(r"""(?P<secret>-----BEGIN (?:EC |DSA )?PRIVATE KEY-----)"""),
        severity="critical",
        description="Private key detected.",
        min_length=5,
    ),
    # --- Database connection strings ---
    SecretPattern(
        id="VP-SEC-017",
        name="Database Connection String",
        pattern=re.compile(
            r"""(?P<secret>(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@\s'"]+@[^\s'"]+)"""
        ),
        severity="high",
        description="Database connection string with embedded credentials detected.",
    ),
    # --- Generic API keys ---
    SecretPattern(
        id="VP-SEC-018",
        name="Generic API Key Assignment",
        pattern=re.compile(
            r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"](?P<secret>[A-Za-z0-9_\-]{20,})['"]""",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Possible API key assignment detected.",
    ),
    SecretPattern(
        id="VP-SEC-019",
        name="Generic Secret Assignment",
        pattern=re.compile(
            r"""(?:secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token)\s*[=:]\s*['"](?P<secret>[^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Possible hardcoded secret or password detected.",
    ),
    # --- Stripe ---
    SecretPattern(
        id="VP-SEC-020",
        name="Stripe Secret Key",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>sk_live_[A-Za-z0-9]{24,})(?:['";\s]|$)"""),
        severity="critical",
        description="Stripe live secret key detected.",
    ),
    SecretPattern(
        id="VP-SEC-021",
        name="Stripe Publishable Key",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>pk_live_[A-Za-z0-9]{24,})(?:['";\s]|$)"""),
        severity="medium",
        description="Stripe live publishable key detected.",
    ),
    # --- SendGrid ---
    SecretPattern(
        id="VP-SEC-022",
        name="SendGrid API Key",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43,})(?:['"\;\s]|$)"""),
        severity="high",
        description="SendGrid API key detected.",
    ),
    # --- Twilio ---
    SecretPattern(
        id="VP-SEC-023",
        name="Twilio API Key",
        pattern=re.compile(r"""(?:^|['"=\s:])(?P<secret>SK[0-9a-fA-F]{32})(?:['";\s]|$)"""),
        severity="high",
        description="Twilio API key detected.",
    ),
    # --- Mailgun ---
    SecretPattern(
        id="VP-SEC-024",
        name="Mailgun API Key",
        pattern=re.compile(
            r"""(?:^|['"=\s:])(?P<secret>key-[0-9a-zA-Z]{32})(?:['";\s]|$)"""
        ),
        severity="high",
        description="Mailgun API key detected.",
    ),
    # --- Heroku ---
    SecretPattern(
        id="VP-SEC-025",
        name="Heroku API Key",
        pattern=re.compile(
            r"""(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*['"]?(?P<secret>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Heroku API key detected.",
    ),
]


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

# Characters typically found in high-entropy secrets
_HEX_CHARS = set("0123456789abcdefABCDEF")
_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

# Entropy thresholds
_HEX_ENTROPY_THRESHOLD = 3.0
_BASE64_ENTROPY_THRESHOLD = 4.5


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns a float representing the bits of entropy per character.
    Higher values indicate more randomness.
    """
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_likely_hex(s: str) -> bool:
    """Check if a string looks like a hex-encoded value."""
    return len(s) >= 16 and all(c in _HEX_CHARS for c in s)


def _is_likely_base64(s: str) -> bool:
    """Check if a string looks like a base64-encoded value."""
    return len(s) >= 20 and all(c in _BASE64_CHARS for c in s)


def detect_high_entropy_strings(
    line: str,
    line_number: int,
    filename: str,
) -> List[Dict[str, Any]]:
    """Detect high-entropy strings that may be secrets.

    Looks for quoted strings with high Shannon entropy that resemble
    hex or base64-encoded secrets.
    """
    findings: List[Dict[str, Any]] = []

    # Extract quoted strings
    for match in re.finditer(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""", line):
        candidate = match.group(1)

        # Skip common false positives
        if _is_false_positive(candidate):
            continue

        entropy = shannon_entropy(candidate)

        if _is_likely_hex(candidate) and entropy >= _HEX_ENTROPY_THRESHOLD:
            findings.append(
                _make_entropy_finding(
                    candidate, entropy, "hex", line_number, filename
                )
            )
        elif _is_likely_base64(candidate) and entropy >= _BASE64_ENTROPY_THRESHOLD:
            findings.append(
                _make_entropy_finding(
                    candidate, entropy, "base64", line_number, filename
                )
            )

    return findings


def _is_false_positive(candidate: str) -> bool:
    """Filter out common false positives for entropy detection."""
    # Common non-secret patterns
    if candidate.startswith(("http://", "https://", "ftp://")):
        return True
    # UUIDs are structured, not secrets
    if re.match(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        candidate,
    ):
        return True
    # Repeated characters
    if len(set(candidate)) < 4:
        return True
    # Common hash algorithm names, encodings, etc.
    lower = candidate.lower()
    if lower in (
        "abcdefghijklmnopqrstuvwxyz",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        "base64",
        "utf-8",
    ):
        return True
    return False


def _make_entropy_finding(
    secret: str,
    entropy: float,
    encoding: str,
    line_number: int,
    filename: str,
) -> Dict[str, Any]:
    """Create a finding dict for a high-entropy string."""
    # Mask the secret for display
    masked = secret[:4] + "..." + secret[-4:] if len(secret) > 12 else "***"
    return {
        "type": "high_entropy_secret",
        "rule_id": "VP-SEC-100",
        "name": f"High-entropy {encoding} string",
        "file": filename,
        "line": line_number,
        "severity": "medium",
        "cwe": "CWE-798",
        "message": f"High-entropy {encoding} string detected (entropy={entropy:.2f}): {masked}",
        "entropy": round(entropy, 2),
        "encoding": encoding,
    }


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

# File extensions to scan
_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".sh", ".bash", ".zsh", ".properties", ".xml",
}

# Files to always skip
_SKIP_PATTERNS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "composer.lock",
    ".min.js", ".min.css", ".map",
}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}


def _should_scan_file(filepath: str) -> bool:
    """Determine if a file should be scanned for secrets."""
    basename = os.path.basename(filepath)
    _, ext = os.path.splitext(basename)

    # Check skip patterns
    for skip in _SKIP_PATTERNS:
        if basename.endswith(skip):
            return False

    # Check extension
    if ext.lower() in _SCANNABLE_EXTENSIONS:
        return True

    # Also scan files without extensions that might be configs
    if not ext and basename.startswith("."):
        return True

    return False


def scan_file_for_secrets(
    filepath: str,
    patterns: Optional[List[SecretPattern]] = None,
    entropy_detection: bool = True,
) -> List[Dict[str, Any]]:
    """Scan a single file for secrets.

    Args:
        filepath: Path to the file to scan.
        patterns: List of SecretPattern objects to match against.
            Defaults to the built-in patterns.
        entropy_detection: Whether to also check for high-entropy strings.

    Returns:
        List of finding dicts.
    """
    if patterns is None:
        patterns = _PATTERNS

    findings: List[Dict[str, Any]] = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                stripped = line.strip()

                # Skip comments (basic heuristic)
                if stripped.startswith(("#", "//", "/*", "*", "<!--")):
                    continue

                # Regex-based detection
                for sp in patterns:
                    match = sp.pattern.search(line)
                    if match:
                        secret_value = match.group("secret")
                        if len(secret_value) < sp.min_length:
                            continue

                        # Mask the secret
                        if len(secret_value) > 12:
                            masked = secret_value[:4] + "..." + secret_value[-4:]
                        else:
                            masked = "***"

                        findings.append({
                            "type": "secret",
                            "rule_id": sp.id,
                            "name": sp.name,
                            "file": filepath,
                            "line": line_number,
                            "severity": sp.severity,
                            "cwe": sp.cwe,
                            "message": f"{sp.description} Value: {masked}",
                            "secret_type": sp.name,
                        })

                # Entropy-based detection
                if entropy_detection:
                    entropy_findings = detect_high_entropy_strings(
                        line, line_number, filepath
                    )
                    findings.extend(entropy_findings)

    except (OSError, UnicodeDecodeError):
        pass

    return findings


def scan_directory_for_secrets(
    directory: str,
    patterns: Optional[List[SecretPattern]] = None,
    entropy_detection: bool = True,
) -> List[Dict[str, Any]]:
    """Scan a directory recursively for secrets.

    Args:
        directory: Path to the directory to scan.
        patterns: List of SecretPattern objects to match against.
        entropy_detection: Whether to also check for high-entropy strings.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        for fname in files:
            fpath = os.path.join(root, fname)
            if _should_scan_file(fpath):
                findings.extend(
                    scan_file_for_secrets(
                        fpath,
                        patterns=patterns,
                        entropy_detection=entropy_detection,
                    )
                )

    return findings


def get_builtin_patterns() -> List[SecretPattern]:
    """Return a copy of the built-in secret detection patterns."""
    return list(_PATTERNS)
