"""Shared type definitions for VulnPredict.

Provides typed data structures for findings and common type aliases used
across the codebase.  Compatible with Python 3.9+ via ``__future__``
annotations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, TypedDict


class Finding(TypedDict, total=False):
    """Typed representation of a single vulnerability finding.

    All keys are optional (``total=False``) because different analyzers
    populate different subsets.
    """

    # Common fields
    type: str
    name: str
    file: str
    function: str
    line: int
    message: str
    rule_id: str
    rule_description: str

    # Severity / scoring
    severity: str
    confidence: str
    vuln_score: float
    combined_score: float

    # Python analyzer fields
    length: int
    dangerous_calls: List[str]
    deserialization_calls: List[str]
    ssrf_calls: List[str]
    path_traversal_calls: List[str]
    xxe_calls: List[str]
    weak_crypto_calls: List[str]
    template_injection_calls: List[str]
    open_redirect_calls: List[str]
    ldap_injection_calls: List[str]
    cyclomatic_complexity: int
    max_nesting_depth: int
    input_validation: List[str]
    sensitive_data_involved: bool
    num_sensitive_vars: int
    embedding: List[float]

    # Taint analysis fields
    source: List[Any]
    sink: str
    sink_line: int
    variable: str
    trace: List[Any]

    # Interprocedural taint fields
    source_func: str
    sink_func: str
    call_chain: List[str]
    tainted_var: str
    var_trace: List[Any]

    # Bandit fields
    test_id: str
    issue_text: str
    line_number: int

    # Dependency fields
    dependencies: List[Dict[str, Any]]
    num_vulnerable_dependencies: int
    num_outdated_dependencies: int
    max_dependency_severity: Optional[str]

    # Git churn fields
    commit_count: int
    unique_authors: int
    last_modified_days: int

    # Suppression fields
    suppression_reason: str

    # ML label
    label: int


# Convenience aliases
FindingList = List[Finding]
"""A list of findings."""

GitChurnFeatures = Dict[str, int]
"""Git churn feature dictionary with commit_count, unique_authors, last_modified_days."""
