"""Severity and confidence scoring framework for VulnPredict findings.

Provides deterministic severity and confidence ratings for each static analysis
rule, independent of the ML model, to deliver consistent and explainable results.
"""

from enum import IntEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """Finding severity levels, ordered from lowest to highest."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a severity string (case-insensitive)."""
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(value.lower(), cls.MEDIUM)

    def __str__(self) -> str:
        return self.name.capitalize()


class Confidence(IntEnum):
    """Finding confidence levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_str(cls, value: str) -> "Confidence":
        """Parse a confidence string (case-insensitive)."""
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
        }
        return mapping.get(value.lower(), cls.MEDIUM)

    def __str__(self) -> str:
        return self.name.capitalize()


# ---------------------------------------------------------------------------
# Rule definitions — maps rule_id -> (severity, confidence, description)
# ---------------------------------------------------------------------------

RULE_REGISTRY = {
    # --- Code execution (Critical) ---
    "PY-EVAL-001": (Severity.CRITICAL, Confidence.HIGH, "Use of eval() with potentially untrusted input"),
    "PY-EXEC-001": (Severity.CRITICAL, Confidence.HIGH, "Use of exec() with potentially untrusted input"),
    "PY-DESER-001": (Severity.CRITICAL, Confidence.HIGH, "Deserialization of untrusted data (pickle/marshal/yaml)"),
    "PY-DESER-002": (Severity.CRITICAL, Confidence.HIGH, "Deserialization via dill/cloudpickle"),
    # --- Injection (High/Critical) ---
    "PY-SQLI-001": (Severity.CRITICAL, Confidence.HIGH, "Potential SQL injection via string formatting"),
    "PY-CMDI-001": (Severity.CRITICAL, Confidence.HIGH, "Command injection via subprocess with shell=True or user input"),
    "PY-LDAP-001": (Severity.HIGH, Confidence.HIGH, "LDAP injection via unsanitized filter input"),
    "PY-TMPL-001": (Severity.HIGH, Confidence.HIGH, "Server-side template injection"),
    # --- Network / Request (High) ---
    "PY-SSRF-001": (Severity.HIGH, Confidence.MEDIUM, "Server-side request forgery via user-controlled URL"),
    "PY-REDIR-001": (Severity.MEDIUM, Confidence.MEDIUM, "Open redirect via user-controlled URL"),
    # --- File system (High) ---
    "PY-PATH-001": (Severity.HIGH, Confidence.MEDIUM, "Path traversal via user-controlled file path"),
    # --- XML (High) ---
    "PY-XXE-001": (Severity.HIGH, Confidence.HIGH, "XML external entity injection via unsafe parser"),
    # --- Cryptography (Medium) ---
    "PY-CRYPTO-001": (Severity.MEDIUM, Confidence.HIGH, "Use of weak cryptographic hash (MD5/SHA1)"),
    "PY-CRYPTO-002": (Severity.MEDIUM, Confidence.HIGH, "Use of weak cipher (DES/ARC4)"),
    # --- Secrets (High) ---
    "PY-SECRET-001": (Severity.HIGH, Confidence.HIGH, "Hardcoded secret or credential in source code"),
    # --- Code quality (Low) ---
    "PY-COMPLEX-001": (Severity.LOW, Confidence.HIGH, "High cyclomatic complexity"),
    "PY-NESTING-001": (Severity.LOW, Confidence.HIGH, "Deeply nested code"),
    # --- Dependency vulnerabilities ---
    "PY-DEP-001": (Severity.HIGH, Confidence.HIGH, "Known vulnerability in Python dependency"),
    # --- JavaScript rules ---
    "JS-EVAL-001": (Severity.CRITICAL, Confidence.HIGH, "Use of eval() in JavaScript"),
    "JS-EXEC-001": (Severity.CRITICAL, Confidence.HIGH, "Use of child_process.exec with user input"),
    "JS-SQLI-001": (Severity.HIGH, Confidence.HIGH, "Potential SQL injection in JavaScript"),
    "JS-XSS-001": (Severity.HIGH, Confidence.HIGH, "DOM-based XSS via innerHTML or document.write"),
    "JS-PROTO-001": (Severity.MEDIUM, Confidence.MEDIUM, "Potential prototype pollution"),
    "JS-DEP-001": (Severity.HIGH, Confidence.HIGH, "Known vulnerability in npm dependency"),
}


# ---------------------------------------------------------------------------
# Finding classification helpers
# ---------------------------------------------------------------------------

def classify_finding(finding: dict) -> dict:
    """Enrich a finding dict with severity, confidence, and rule_id.

    This function examines the finding's attributes (dangerous_calls,
    deserialization_calls, etc.) and assigns the most severe applicable rule.

    Args:
        finding: A raw finding dict from an analyzer.

    Returns:
        The same dict, enriched with 'severity', 'confidence', 'rule_id',
        'rule_description', and 'combined_score' fields.
    """
    best_rule_id = None
    best_severity = Severity.LOW
    best_confidence = Confidence.LOW
    best_description = ""

    # Check each category and assign the highest-severity matching rule
    rules_to_check = _match_rules(finding)

    for rule_id in rules_to_check:
        if rule_id not in RULE_REGISTRY:
            continue
        sev, conf, desc = RULE_REGISTRY[rule_id]
        if sev > best_severity or (sev == best_severity and conf > best_confidence):
            best_rule_id = rule_id
            best_severity = sev
            best_confidence = conf
            best_description = desc

    # If no rule matched, assign a default LOW severity
    if best_rule_id is None:
        best_rule_id = "UNKNOWN"
        best_severity = Severity.LOW
        best_confidence = Confidence.LOW
        best_description = "Unclassified finding"

    # Compute combined score: merge static severity with ML vuln_score
    ml_score = finding.get("vuln_score", 0.5)
    combined = compute_combined_score(best_severity, best_confidence, ml_score)

    finding["severity"] = str(best_severity)
    finding["confidence"] = str(best_confidence)
    finding["rule_id"] = best_rule_id
    finding["rule_description"] = best_description
    finding["combined_score"] = round(combined, 3)

    return finding


def _match_rules(finding: dict) -> list:
    """Determine which rule IDs apply to a finding based on its attributes."""
    matched = []

    # Dangerous calls (eval, exec, subprocess)
    for call in finding.get("dangerous_calls", []):
        if "eval" in call:
            matched.append("PY-EVAL-001")
        elif "exec" in call and "subprocess" not in call:
            matched.append("PY-EXEC-001")
        elif "subprocess" in call or "os.system" in call or "os.popen" in call:
            matched.append("PY-CMDI-001")

    # Deserialization
    for call in finding.get("deserialization_calls", []):
        if any(lib in call for lib in ("dill", "cloudpickle")):
            matched.append("PY-DESER-002")
        else:
            matched.append("PY-DESER-001")

    # SSRF
    if finding.get("ssrf_calls"):
        matched.append("PY-SSRF-001")

    # Path traversal
    if finding.get("path_traversal_calls"):
        matched.append("PY-PATH-001")

    # XXE
    if finding.get("xxe_calls"):
        matched.append("PY-XXE-001")

    # Weak crypto
    for call in finding.get("weak_crypto_calls", []):
        if any(cipher in call for cipher in ("DES", "ARC4")):
            matched.append("PY-CRYPTO-002")
        else:
            matched.append("PY-CRYPTO-001")

    # Template injection
    if finding.get("template_injection_calls"):
        matched.append("PY-TMPL-001")

    # Open redirect
    if finding.get("open_redirect_calls"):
        matched.append("PY-REDIR-001")

    # LDAP injection
    if finding.get("ldap_injection_calls"):
        matched.append("PY-LDAP-001")

    # Secrets
    if finding.get("sensitive_data_involved"):
        matched.append("PY-SECRET-001")

    # Complexity
    complexity = finding.get("cyclomatic_complexity", 0)
    if complexity > 15:
        matched.append("PY-COMPLEX-001")

    nesting = finding.get("max_nesting_depth", 0)
    if nesting > 5:
        matched.append("PY-NESTING-001")

    return matched


def compute_combined_score(
    severity: Severity,
    confidence: Confidence,
    ml_score: float,
    static_weight: float = 0.6,
    ml_weight: float = 0.4,
) -> float:
    """Compute a combined score merging static severity with ML prediction.

    The static component normalizes severity (1-4) and confidence (1-3) to
    a 0-1 scale, then blends with the ML vuln_score.

    Args:
        severity: The deterministic severity level.
        confidence: The deterministic confidence level.
        ml_score: The ML model's vulnerability probability (0-1).
        static_weight: Weight for the static analysis component (default 0.6).
        ml_weight: Weight for the ML component (default 0.4).

    Returns:
        A combined score between 0 and 1.
    """
    # Normalize severity to 0-1 (LOW=0.25, MEDIUM=0.5, HIGH=0.75, CRITICAL=1.0)
    severity_norm = severity.value / 4.0

    # Normalize confidence to 0-1 (LOW=0.33, MEDIUM=0.67, HIGH=1.0)
    confidence_norm = confidence.value / 3.0

    # Static score is severity weighted by confidence
    static_score = severity_norm * confidence_norm

    # Blend static and ML scores
    combined = (static_weight * static_score) + (ml_weight * float(ml_score))

    return min(max(combined, 0.0), 1.0)


def filter_by_severity(findings: list, min_severity: str) -> list:
    """Filter findings to only include those at or above the minimum severity.

    Args:
        findings: List of enriched finding dicts with 'severity' field.
        min_severity: Minimum severity string (e.g., 'high').

    Returns:
        Filtered list of findings.
    """
    threshold = Severity.from_str(min_severity)
    return [
        f for f in findings
        if Severity.from_str(f.get("severity", "low")) >= threshold
    ]


def sort_by_severity(findings: list, descending: bool = True) -> list:
    """Sort findings by severity (and combined_score as tiebreaker).

    Args:
        findings: List of enriched finding dicts.
        descending: If True, most severe findings come first.

    Returns:
        Sorted list of findings.
    """
    def sort_key(f):
        sev = Severity.from_str(f.get("severity", "low"))
        score = f.get("combined_score", 0.0)
        return (sev, score)

    return sorted(findings, key=sort_key, reverse=descending)
