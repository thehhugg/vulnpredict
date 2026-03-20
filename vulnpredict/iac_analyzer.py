"""Infrastructure-as-Code (IaC) security analyzer.

Detects security misconfigurations in:
- **Terraform** (.tf) — S3 buckets, security groups, IAM policies, RDS
- **Dockerfile** — root user, latest tag, secrets, ADD vs COPY
- **Kubernetes** (.yaml/.yml) — privileged containers, resource limits, host sharing
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Terraform patterns
# ---------------------------------------------------------------------------

_TF_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "VP-TF-001",
        "name": "S3 Bucket Without Encryption",
        "pattern": re.compile(
            r'resource\s+"aws_s3_bucket"\s+"[^"]*"', re.IGNORECASE
        ),
        "anti_pattern": re.compile(
            r"server_side_encryption_configuration|aws_s3_bucket_server_side_encryption",
            re.IGNORECASE,
        ),
        "block_scope": True,
        "severity": "high",
        "cwe": "CWE-311",
        "message": "S3 bucket defined without server-side encryption configuration",
    },
    {
        "rule_id": "VP-TF-002",
        "name": "Overly Permissive Security Group",
        "pattern": re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'),
        "anti_pattern": None,
        "block_scope": False,
        "severity": "high",
        "cwe": "CWE-284",
        "message": "Security group allows traffic from 0.0.0.0/0 (all IPs)",
    },
    {
        "rule_id": "VP-TF-003",
        "name": "IAM Wildcard Permissions",
        "pattern": re.compile(r'"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]'),
        "anti_pattern": None,
        "block_scope": False,
        "severity": "critical",
        "cwe": "CWE-250",
        "message": "IAM policy grants wildcard (*) permissions",
    },
    {
        "rule_id": "VP-TF-004",
        "name": "Unencrypted RDS Instance",
        "pattern": re.compile(
            r'resource\s+"aws_db_instance"\s+"[^"]*"', re.IGNORECASE
        ),
        "anti_pattern": re.compile(r"storage_encrypted\s*=\s*true", re.IGNORECASE),
        "block_scope": True,
        "severity": "high",
        "cwe": "CWE-311",
        "message": "RDS instance defined without storage encryption enabled",
    },
    {
        "rule_id": "VP-TF-005",
        "name": "Overly Permissive IPv6 Security Group",
        "pattern": re.compile(r'ipv6_cidr_blocks\s*=\s*\[\s*"::/0"\s*\]'),
        "anti_pattern": None,
        "block_scope": False,
        "severity": "high",
        "cwe": "CWE-284",
        "message": "Security group allows traffic from ::/0 (all IPv6 addresses)",
    },
]

# ---------------------------------------------------------------------------
# Dockerfile patterns
# ---------------------------------------------------------------------------

_DOCKERFILE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "VP-DF-001",
        "name": "Running as Root",
        "check": "no_user_directive",
        "severity": "high",
        "cwe": "CWE-250",
        "message": "Dockerfile does not set a non-root USER; container will run as root",
    },
    {
        "rule_id": "VP-DF-002",
        "name": "Latest Tag Used",
        "pattern": re.compile(r"^FROM\s+\S+:latest\b", re.IGNORECASE),
        "severity": "medium",
        "cwe": "CWE-829",
        "message": "Dockerfile uses :latest tag; pin to a specific version for reproducibility",
    },
    {
        "rule_id": "VP-DF-003",
        "name": "FROM Without Tag",
        "pattern": re.compile(r"^FROM\s+([a-zA-Z0-9._/-]+)\s*$"),
        "severity": "medium",
        "cwe": "CWE-829",
        "message": "Dockerfile FROM without a tag defaults to :latest; pin to a specific version",
    },
    {
        "rule_id": "VP-DF-004",
        "name": "Secrets in COPY/ADD",
        "pattern": re.compile(
            r"^(?:COPY|ADD)\s+.*(?:\.env|\.pem|id_rsa|\.key|password|secret|credentials)",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "cwe": "CWE-540",
        "message": "Potentially copying secrets or credentials into the Docker image",
    },
    {
        "rule_id": "VP-DF-005",
        "name": "ADD with Remote URL",
        "pattern": re.compile(r"^ADD\s+https?://", re.IGNORECASE),
        "severity": "medium",
        "cwe": "CWE-829",
        "message": "Using ADD with a remote URL; prefer COPY with explicit download for verification",
    },
    {
        "rule_id": "VP-DF-006",
        "name": "Explicit Root USER",
        "pattern": re.compile(r"^USER\s+root\s*$", re.IGNORECASE),
        "severity": "high",
        "cwe": "CWE-250",
        "message": "Dockerfile explicitly sets USER to root",
    },
]

# ---------------------------------------------------------------------------
# Kubernetes patterns
# ---------------------------------------------------------------------------

_K8S_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "VP-K8-001",
        "name": "Privileged Container",
        "pattern": re.compile(r"privileged:\s*true"),
        "severity": "critical",
        "cwe": "CWE-250",
        "message": "Container runs in privileged mode, granting full host access",
    },
    {
        "rule_id": "VP-K8-002",
        "name": "Running as Root",
        "pattern": re.compile(r"runAsUser:\s*0\b"),
        "severity": "high",
        "cwe": "CWE-250",
        "message": "Container configured to run as root (UID 0)",
    },
    {
        "rule_id": "VP-K8-003",
        "name": "Host Network Enabled",
        "pattern": re.compile(r"hostNetwork:\s*true"),
        "severity": "high",
        "cwe": "CWE-284",
        "message": "Pod uses host network namespace, bypassing network isolation",
    },
    {
        "rule_id": "VP-K8-004",
        "name": "Host PID Enabled",
        "pattern": re.compile(r"hostPID:\s*true"),
        "severity": "high",
        "cwe": "CWE-284",
        "message": "Pod uses host PID namespace, allowing process visibility",
    },
    {
        "rule_id": "VP-K8-005",
        "name": "Missing Resource Limits",
        "check": "no_resource_limits",
        "severity": "medium",
        "cwe": "CWE-770",
        "message": "Container spec missing resource limits; may cause resource exhaustion",
    },
    {
        "rule_id": "VP-K8-006",
        "name": "Allow Privilege Escalation",
        "pattern": re.compile(r"allowPrivilegeEscalation:\s*true"),
        "severity": "high",
        "cwe": "CWE-250",
        "message": "Container allows privilege escalation",
    },
]


# ---------------------------------------------------------------------------
# Terraform scanning
# ---------------------------------------------------------------------------


def _extract_tf_blocks(content: str) -> List[Dict[str, Any]]:
    """Extract top-level resource blocks from Terraform content.

    Returns a list of dicts with 'start_line', 'end_line', and 'text'.
    """
    blocks: List[Dict[str, Any]] = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r'\s*resource\s+"', line):
            start = i
            depth = 0
            block_lines = []
            for j in range(i, len(lines)):
                block_lines.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and j > i:
                    blocks.append({
                        "start_line": start + 1,
                        "end_line": j + 1,
                        "text": "\n".join(block_lines),
                    })
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1
    return blocks


def scan_terraform_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a Terraform file for security misconfigurations."""
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.split("\n")
    blocks = _extract_tf_blocks(content)

    for rule in _TF_RULES:
        if rule.get("block_scope"):
            # Check within resource blocks
            for block in blocks:
                if rule["pattern"].search(block["text"]):
                    if rule["anti_pattern"] and rule["anti_pattern"].search(
                        block["text"]
                    ):
                        continue
                    findings.append({
                        "type": "iac_misconfiguration",
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "file": filepath,
                        "line": block["start_line"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "message": rule["message"],
                    })
        else:
            # Line-by-line matching
            for i, line in enumerate(lines, 1):
                if rule["pattern"].search(line):
                    findings.append({
                        "type": "iac_misconfiguration",
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "file": filepath,
                        "line": i,
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "message": rule["message"],
                    })

    return findings


# ---------------------------------------------------------------------------
# Dockerfile scanning
# ---------------------------------------------------------------------------


def scan_dockerfile(filepath: str) -> List[Dict[str, Any]]:
    """Scan a Dockerfile for security misconfigurations."""
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    has_user_directive = False
    has_from = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.upper().startswith("FROM"):
            has_from = True

        if stripped.upper().startswith("USER") and not re.match(
            r"USER\s+root\s*$", stripped, re.IGNORECASE
        ):
            has_user_directive = True

        for rule in _DOCKERFILE_RULES:
            if "pattern" in rule and rule["pattern"].search(stripped):
                findings.append({
                    "type": "iac_misconfiguration",
                    "rule_id": rule["rule_id"],
                    "name": rule["name"],
                    "file": filepath,
                    "line": i,
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "message": rule["message"],
                })

    # Check for missing USER directive (VP-DF-001)
    if has_from and not has_user_directive:
        findings.append({
            "type": "iac_misconfiguration",
            "rule_id": "VP-DF-001",
            "name": "Running as Root",
            "file": filepath,
            "line": 1,
            "severity": "high",
            "cwe": "CWE-250",
            "message": "Dockerfile does not set a non-root USER; container will run as root",
        })

    return findings


# ---------------------------------------------------------------------------
# Kubernetes scanning
# ---------------------------------------------------------------------------


def _is_k8s_manifest(content: str) -> bool:
    """Heuristically check if a YAML file is a Kubernetes manifest."""
    return bool(
        re.search(r"apiVersion:", content) and re.search(r"kind:", content)
    )


def _has_resource_limits(content: str) -> bool:
    """Check if a Kubernetes manifest has resource limits defined."""
    return bool(re.search(r"resources:", content) and re.search(r"limits:", content))


def scan_kubernetes_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a Kubernetes YAML manifest for security misconfigurations."""
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings

    if not _is_k8s_manifest(content):
        return findings

    lines = content.split("\n")

    for rule in _K8S_RULES:
        if "pattern" in rule:
            for i, line in enumerate(lines, 1):
                if rule["pattern"].search(line):
                    findings.append({
                        "type": "iac_misconfiguration",
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "file": filepath,
                        "line": i,
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "message": rule["message"],
                    })

    # Check for missing resource limits (VP-K8-005)
    if re.search(r"containers:", content) and not _has_resource_limits(content):
        findings.append({
            "type": "iac_misconfiguration",
            "rule_id": "VP-K8-005",
            "name": "Missing Resource Limits",
            "file": filepath,
            "line": 1,
            "severity": "medium",
            "cwe": "CWE-770",
            "message": "Container spec missing resource limits; may cause resource exhaustion",
        })

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_iac_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a single IaC file based on its extension/name.

    Dispatches to the appropriate scanner based on file type.
    """
    basename = os.path.basename(filepath).lower()

    if filepath.endswith(".tf"):
        return scan_terraform_file(filepath)
    if basename.startswith("dockerfile") or basename == "containerfile":
        return scan_dockerfile(filepath)
    if filepath.endswith((".yaml", ".yml")):
        return scan_kubernetes_file(filepath)

    return []


def scan_iac_directory(directory: str) -> List[Dict[str, Any]]:
    """Scan a directory recursively for IaC security misconfigurations.

    Detects and scans:
    - Terraform files (.tf)
    - Dockerfiles (Dockerfile, Dockerfile.*, Containerfile)
    - Kubernetes manifests (.yaml, .yml with apiVersion/kind)
    """
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".terraform",
        "dist", "build", ".next", "vendor",
    }
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = os.path.join(root, fname)
            lower = fname.lower()
            if (
                lower.endswith(".tf")
                or lower.startswith("dockerfile")
                or lower == "containerfile"
                or lower.endswith((".yaml", ".yml"))
            ):
                findings.extend(scan_iac_file(fpath))

    return findings
