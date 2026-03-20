"""JSON output formatter for VulnPredict scan results.

Produces a stable, documented JSON schema containing:
- Metadata (tool version, scan timestamp, duration, file count)
- Summary (total findings, breakdown by severity)
- Findings array with normalized structure
"""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Version is read from pyproject.toml at import time; fallback to "dev"
try:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

    import os

    _pyproject = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
    if os.path.isfile(_pyproject):
        with open(_pyproject, "rb") as _f:
            _VERSION = tomllib.load(_f).get("project", {}).get("version", "dev")
    else:
        _VERSION = "dev"
except Exception:
    _VERSION = "dev"

# JSON output schema version — bump on breaking changes
SCHEMA_VERSION = "1.0.0"


def _classify_severity(finding: Dict[str, Any]) -> str:
    """Classify a finding into a severity level.

    Uses vuln_score if available (from ML model), otherwise falls back to
    heuristic classification based on finding type and sink.
    """
    score = finding.get("vuln_score")
    if score is not None:
        if score >= 0.8:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    # Heuristic fallback based on finding type and sink
    ftype = finding.get("type", "")
    sink = str(finding.get("sink", finding.get("function", "")))

    high_sinks = {"eval", "exec", "os.system", "subprocess.call", "cursor.execute"}
    medium_sinks = {"open", "pickle.loads", "yaml.load", "marshal.loads"}

    if ftype == "interprocedural_taint":
        return "high"
    if sink in high_sinks:
        return "high"
    if sink in medium_sinks:
        return "medium"
    if ftype == "hardcoded_secret":
        return "high"
    if ftype == "dangerous_function":
        return "medium"
    return "low"


def _normalize_finding(finding: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Normalize a raw finding dict into a stable output structure."""
    severity = _classify_severity(finding)
    ftype = finding.get("type", "unknown")

    normalized = {
        "id": f"VP-{index:04d}",
        "type": ftype,
        "severity": severity,
    }

    # File location
    if "file" in finding:
        normalized["file"] = finding["file"]
    if "filename" in finding:
        normalized["file"] = finding["filename"]

    # Line number
    if "line" in finding:
        normalized["line"] = finding["line"]
    elif "sink_line" in finding:
        normalized["line"] = finding["sink_line"]

    # Message / description
    if ftype == "taint_analysis":
        src = finding.get("source", [])
        sink = finding.get("sink", "unknown")
        var = finding.get("variable", "unknown")
        normalized["message"] = (
            f"Tainted variable '{var}' flows from source to dangerous sink '{sink}'"
        )
        normalized["sink"] = sink
        normalized["variable"] = var
        if "trace" in finding:
            normalized["trace"] = finding["trace"]
    elif ftype == "interprocedural_taint":
        normalized["message"] = (
            f"Interprocedural taint flow: {finding.get('tainted_var', '?')} "
            f"reaches sink '{finding.get('sink', '?')}' via call chain"
        )
        normalized["sink"] = finding.get("sink", "unknown")
        normalized["variable"] = finding.get("tainted_var", "unknown")
        if "call_chain" in finding:
            normalized["call_chain"] = finding["call_chain"]
        if "source_func" in finding:
            normalized["source_function"] = finding["source_func"]
        if "sink_func" in finding:
            normalized["sink_function"] = finding["sink_func"]
    elif ftype == "dangerous_function":
        func = finding.get("function", "unknown")
        normalized["message"] = f"Dangerous function call: {func}"
        normalized["function"] = func
    elif ftype == "hardcoded_secret":
        normalized["message"] = (
            f"Hardcoded secret detected: {finding.get('variable', '?')}"
        )
        normalized["variable"] = finding.get("variable", "unknown")
    elif ftype == "high_complexity":
        normalized["message"] = (
            f"High cyclomatic complexity: {finding.get('complexity', '?')}"
        )
        normalized["complexity"] = finding.get("complexity")
    else:
        normalized["message"] = finding.get("message", str(finding))

    # Preserve ML score if present
    if "vuln_score" in finding:
        normalized["confidence"] = finding["vuln_score"]

    return normalized


def format_json(
    findings: List[Dict[str, Any]],
    scan_path: str,
    scan_duration: Optional[float] = None,
    file_count: Optional[int] = None,
    compact: bool = False,
) -> str:
    """Format scan findings as a JSON string.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.
        scan_duration: Scan duration in seconds (optional).
        file_count: Number of files scanned (optional).
        compact: If True, produce minified JSON; otherwise pretty-print.

    Returns:
        JSON string with the complete scan report.
    """
    # Normalize all findings
    normalized = [_normalize_finding(f, i + 1) for i, f in enumerate(findings)]

    # Build severity summary
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for f in normalized:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    output = {
        "$schema": "vulnpredict-json-v1",
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "tool": "vulnpredict",
            "version": _VERSION,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_path": scan_path,
        },
        "summary": {
            "total_findings": len(normalized),
            "by_severity": severity_counts,
        },
        "findings": normalized,
    }

    if scan_duration is not None:
        output["metadata"]["scan_duration_seconds"] = round(scan_duration, 3)
    if file_count is not None:
        output["metadata"]["files_scanned"] = file_count

    if compact:
        return json.dumps(output, separators=(",", ":"), default=str)
    return json.dumps(output, indent=2, default=str)


def write_json(
    findings: List[Dict[str, Any]],
    scan_path: str,
    output_path: str,
    scan_duration: Optional[float] = None,
    file_count: Optional[int] = None,
    compact: bool = False,
) -> None:
    """Format and write scan findings to a JSON file.

    Args:
        findings: List of raw finding dicts from analyzers.
        scan_path: The path that was scanned.
        output_path: Path to write the JSON output file.
        scan_duration: Scan duration in seconds (optional).
        file_count: Number of files scanned (optional).
        compact: If True, produce minified JSON; otherwise pretty-print.
    """
    json_str = format_json(
        findings,
        scan_path,
        scan_duration=scan_duration,
        file_count=file_count,
        compact=compact,
    )
    with open(output_path, "w") as f:
        f.write(json_str)
        f.write("\n")
