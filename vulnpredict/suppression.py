"""Finding suppression and ignore mechanism for VulnPredict.

Supports:
- Inline comments: ``# vulnpredict-ignore: RULE_ID`` and ``# vulnpredict-ignore-line``
- ``.vulnpredictignore`` file with gitignore-style path patterns
- Baseline comparison to surface only new findings
"""

import fnmatch
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vulnpredict.suppression")

# ---------------------------------------------------------------------------
# Inline suppression markers
# ---------------------------------------------------------------------------

# Matches: # vulnpredict-ignore: RULE_ID[, RULE_ID, ...]
_IGNORE_RULE_RE = re.compile(
    r"#\s*vulnpredict-ignore:\s*(.+)", re.IGNORECASE
)

# Matches: # vulnpredict-ignore-line
_IGNORE_LINE_RE = re.compile(
    r"#\s*vulnpredict-ignore-line", re.IGNORECASE
)

# JS-style inline comments
_JS_IGNORE_RULE_RE = re.compile(
    r"//\s*vulnpredict-ignore:\s*(.+)", re.IGNORECASE
)
_JS_IGNORE_LINE_RE = re.compile(
    r"//\s*vulnpredict-ignore-line", re.IGNORECASE
)


def parse_inline_suppressions(filepath: str) -> Tuple[Dict[int, Set[str]], Set[int]]:
    """Parse inline suppression comments from a source file.

    Returns:
        A tuple of:
        - ``rule_suppressions``: mapping of line number → set of suppressed rule IDs
        - ``line_suppressions``: set of line numbers where all findings are suppressed
    """
    rule_suppressions: Dict[int, Set[str]] = {}
    line_suppressions: Set[int] = set()

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                # Check Python-style comments
                m = _IGNORE_RULE_RE.search(line)
                if m:
                    rules = {r.strip().upper() for r in m.group(1).split(",")}
                    rule_suppressions.setdefault(lineno, set()).update(rules)
                    continue

                if _IGNORE_LINE_RE.search(line):
                    line_suppressions.add(lineno)
                    continue

                # Check JS-style comments
                m = _JS_IGNORE_RULE_RE.search(line)
                if m:
                    rules = {r.strip().upper() for r in m.group(1).split(",")}
                    rule_suppressions.setdefault(lineno, set()).update(rules)
                    continue

                if _JS_IGNORE_LINE_RE.search(line):
                    line_suppressions.add(lineno)
    except OSError as exc:
        logger.warning("Could not read %s for inline suppressions: %s", filepath, exc)

    return rule_suppressions, line_suppressions


# ---------------------------------------------------------------------------
# .vulnpredictignore file
# ---------------------------------------------------------------------------


class IgnoreFile:
    """Gitignore-style file/directory exclusion patterns.

    Reads patterns from a ``.vulnpredictignore`` file and provides a method
    to check whether a given file path should be ignored.
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        self._patterns: List[str] = patterns or []

    @classmethod
    def from_file(cls, path: str) -> "IgnoreFile":
        """Load patterns from a ``.vulnpredictignore`` file."""
        patterns: List[str] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue
                    patterns.append(line)
            logger.info("Loaded %d ignore patterns from %s", len(patterns), path)
        except FileNotFoundError:
            logger.debug("No .vulnpredictignore file found at %s", path)
        except OSError as exc:
            logger.warning("Could not read ignore file %s: %s", path, exc)
        return cls(patterns)

    @classmethod
    def from_project(cls, project_dir: str) -> "IgnoreFile":
        """Load ``.vulnpredictignore`` from the root of a project directory."""
        return cls.from_file(os.path.join(project_dir, ".vulnpredictignore"))

    def is_ignored(self, filepath: str, project_root: str = "") -> bool:
        """Check if *filepath* matches any ignore pattern.

        Matching is performed against the path relative to *project_root*.
        Supports gitignore-style patterns: ``*.log``, ``build/``, ``**/test_*``.
        """
        if not self._patterns:
            return False

        if project_root:
            try:
                rel = os.path.relpath(filepath, project_root)
            except ValueError:
                rel = filepath
        else:
            rel = filepath

        # Normalise to forward slashes for consistent matching
        rel = rel.replace(os.sep, "/")

        for pattern in self._patterns:
            # Directory pattern (trailing slash)
            if pattern.endswith("/"):
                dir_pattern = pattern.rstrip("/")
                # Match exact directory components only (not substrings)
                parts = rel.split("/")
                # Check if any directory component exactly matches
                # e.g., "build/" matches "build/out.py" and "src/build/out.py"
                # but NOT "my_build/out.py"
                for part in parts[:-1]:  # Exclude filename, only check dirs
                    if fnmatch.fnmatch(part, dir_pattern):
                        return True
                # Also check if the relative path starts with the dir pattern
                if rel.startswith(dir_pattern + "/"):
                    return True
                continue

            # Handle ** patterns (gitignore double-star)
            if "**" in pattern:
                # Split pattern on ** and process each segment
                segments = pattern.split("**")
                # Strip slashes between ** and adjacent segments
                cleaned = []
                for seg in segments:
                    seg = seg.strip("/")
                    if seg:
                        escaped = re.escape(seg)
                        escaped = escaped.replace(r"\*", "[^/]*")
                        escaped = escaped.replace(r"\?", "[^/]")
                        cleaned.append(escaped)
                    else:
                        cleaned.append("")
                # Join with regex that matches zero or more path segments
                non_empty = [c for c in cleaned if c]
                regex = "(?:.+/)?" .join(non_empty)
                # If pattern starts with **, allow matching from any depth
                if pattern.startswith("**"):
                    regex = "(?:.*/)?"+regex
                if re.match(regex + "$", rel):
                    return True
                continue

            # Standard glob matching against full relative path
            if fnmatch.fnmatch(rel, pattern):
                return True

            # Also match against just the filename (gitignore behavior)
            if "/" not in pattern and fnmatch.fnmatch(os.path.basename(rel), pattern):
                return True

        return False

    @property
    def patterns(self) -> List[str]:
        """Return the list of loaded patterns."""
        return list(self._patterns)


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------


def load_baseline(path: str) -> List[Dict[str, Any]]:
    """Load a baseline scan result from a JSON file.

    The baseline file is expected to be the JSON output of a previous
    ``vulnpredict scan --format json`` run.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        findings: List[Dict[str, Any]] = data.get("findings", [])
        logger.info("Loaded baseline with %d findings from %s", len(findings), path)
        return findings
    except FileNotFoundError:
        logger.warning("Baseline file not found: %s", path)
        return []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load baseline from %s: %s", path, exc)
        return []


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Create a stable fingerprint for a finding to enable deduplication.

    The fingerprint is based on file, line, rule, and message — but not
    on the exact column or severity, which may change between runs.
    """
    parts = [
        finding.get("file", ""),
        str(finding.get("line", "")),
        finding.get("rule_id", finding.get("type", "")),
        finding.get("message", finding.get("description", "")),
    ]
    return "|".join(parts)


def _finding_fuzzy_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Create a fuzzy key for baseline matching (file + rule_id + message).

    This key omits the line number so that findings that moved by a few
    lines (due to small code edits) are still recognised as known.
    """
    return (
        finding.get("file", ""),
        finding.get("rule_id", finding.get("type", "")),
        finding.get("message", finding.get("description", "")),
    )


def filter_by_baseline(
    findings: List[Dict[str, Any]],
    baseline: List[Dict[str, Any]],
    *,
    fuzzy_lines: int = 5,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Partition *findings* into new and baseline-known findings.

    Matching strategy:
    1. **Exact match** — file + line + rule_id + message.
    2. **Fuzzy match** — file + rule_id + message with a line-number
       tolerance of *fuzzy_lines* (default 5).

    Returns:
        A tuple of (new_findings, known_findings).
    """
    # Build exact fingerprint set
    baseline_fps = {_finding_fingerprint(f) for f in baseline}

    # Build fuzzy index: (file, rule_id, message) -> set of line numbers
    fuzzy_index: Dict[Tuple[str, str, str], set] = {}
    for f in baseline:
        key = _finding_fuzzy_key(f)
        fuzzy_index.setdefault(key, set()).add(f.get("line", 0))

    new = []
    known = []
    for f in findings:
        # 1. Exact match
        if _finding_fingerprint(f) in baseline_fps:
            known.append(f)
            continue

        # 2. Fuzzy match (same file + rule + message, line within tolerance)
        fkey = _finding_fuzzy_key(f)
        if fkey in fuzzy_index:
            fline = f.get("line", 0)
            if any(abs(fline - bl) <= fuzzy_lines for bl in fuzzy_index[fkey]):
                known.append(f)
                continue

        new.append(f)

    logger.info(
        "Baseline comparison: %d new, %d known (suppressed)",
        len(new),
        len(known),
    )
    return new, known


def save_baseline(
    findings: List[Dict[str, Any]],
    output_path: str,
    scan_path: str = "",
    scan_duration: float = 0.0,
    file_count: int = 0,
) -> None:
    """Save the current scan results as a baseline file (JSON format).

    The file uses the same schema as ``vulnpredict scan --format json``
    so it can be loaded by :func:`load_baseline`.
    """
    from .formatters.json_fmt import format_json

    json_str = format_json(
        findings,
        scan_path=scan_path,
        scan_duration=scan_duration,
        file_count=file_count,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)
        f.write("\n")
    logger.info("Baseline saved to %s (%d findings)", output_path, len(findings))


# ---------------------------------------------------------------------------
# Apply suppressions to findings
# ---------------------------------------------------------------------------


def apply_suppressions(
    findings: List[Dict[str, Any]],
    project_root: str = "",
    ignore_file: Optional[IgnoreFile] = None,
    baseline: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply all suppression mechanisms to a list of findings.

    Suppression sources (checked in order):
    1. ``.vulnpredictignore`` file patterns
    2. Inline ``# vulnpredict-ignore-line`` comments
    3. Inline ``# vulnpredict-ignore: RULE_ID`` comments
    4. Baseline comparison (if provided)

    Returns:
        A tuple of (active_findings, suppressed_findings).
    """
    if ignore_file is None:
        ignore_file = IgnoreFile()

    active: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []

    # Cache inline suppressions per file
    _inline_cache: Dict[str, Tuple[Dict[int, Set[str]], Set[int]]] = {}

    for finding in findings:
        filepath = finding.get("file", "")
        line = finding.get("line")
        rule_id = finding.get("rule_id", finding.get("type", "")).upper()

        # 1. Check .vulnpredictignore
        if filepath and ignore_file.is_ignored(filepath, project_root):
            finding["suppression_reason"] = "ignore_file"
            suppressed.append(finding)
            continue

        # 2 & 3. Check inline suppressions
        if filepath and line is not None:
            full_path = filepath
            if project_root and not os.path.isabs(filepath):
                full_path = os.path.join(project_root, filepath)

            if full_path not in _inline_cache:
                _inline_cache[full_path] = parse_inline_suppressions(full_path)

            rule_supps, line_supps = _inline_cache[full_path]

            if line in line_supps:
                finding["suppression_reason"] = "inline_ignore_line"
                suppressed.append(finding)
                continue

            if line in rule_supps and rule_id in rule_supps[line]:
                finding["suppression_reason"] = "inline_ignore_rule"
                suppressed.append(finding)
                continue

        active.append(finding)

    # 4. Baseline comparison
    if baseline is not None:
        new_active, baseline_suppressed = filter_by_baseline(active, baseline)
        for f in baseline_suppressed:
            f["suppression_reason"] = "baseline"
        suppressed.extend(baseline_suppressed)
        active = new_active

    logger.info(
        "Suppression results: %d active, %d suppressed",
        len(active),
        len(suppressed),
    )
    return active, suppressed
