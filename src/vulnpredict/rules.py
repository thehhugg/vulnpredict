"""Configurable rule engine with YAML-based custom rules.

Loads detection rules from YAML files and provides a unified interface for
the analyzers to evaluate findings against both built-in and user-defined rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import yaml

from .logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

REQUIRED_RULE_FIELDS = {"id", "name", "severity", "message", "pattern"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CONFIDENCES = {"high", "medium", "low"}
VALID_PATTERN_TYPES = {"function_call", "import", "attribute_access", "string_match"}
VALID_LANGUAGES = {"python", "javascript", "typescript", "go"}

# Built-in rules directory (ships with the package)
BUILTIN_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "rules")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RulePattern:
    """A pattern that a rule matches against."""

    type: str  # function_call, import, attribute_access, string_match
    name: Optional[str] = None  # function/import name to match
    names: Optional[List[str]] = None  # multiple names (OR match)
    regex: Optional[str] = None  # regex pattern for string_match

    def matches_function(self, func_name: str) -> bool:
        """Check if a function call matches this pattern."""
        if self.type != "function_call":
            return False
        if self.name and func_name == self.name:
            return True
        if self.names and func_name in self.names:
            return True
        return False

    def get_all_names(self) -> Set[str]:
        """Return all function/import names this pattern matches."""
        result: Set[str] = set()
        if self.name:
            result.add(self.name)
        if self.names:
            result.update(self.names)
        return result


@dataclass
class Rule:
    """A vulnerability detection rule."""

    id: str
    name: str
    severity: str
    message: str
    pattern: RulePattern
    confidence: str = "medium"
    languages: List[str] = field(default_factory=lambda: ["python"])
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    category: str = "general"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    source_file: Optional[str] = None

    @property
    def rule_description(self) -> str:
        """Human-readable description combining message and CWE."""
        if self.cwe:
            return f"{self.message} ({self.cwe})"
        return self.message


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class RuleValidationError(Exception):
    """Raised when a rule file contains invalid data."""


def validate_rule_dict(data: Dict[str, Any], source: str = "<unknown>") -> List[str]:
    """Validate a rule dictionary and return a list of error messages.

    Returns an empty list if the rule is valid.
    """
    errors: List[str] = []

    # Required fields
    for field_name in REQUIRED_RULE_FIELDS:
        if field_name not in data:
            errors.append(f"Missing required field '{field_name}' in rule from {source}")

    rule_id = data.get("id", "<no-id>")

    # Severity
    sev = data.get("severity", "").lower()
    if sev and sev not in VALID_SEVERITIES:
        errors.append(
            f"Rule {rule_id}: invalid severity '{sev}'. "
            f"Must be one of {sorted(VALID_SEVERITIES)}"
        )

    # Confidence
    conf = data.get("confidence", "medium").lower()
    if conf not in VALID_CONFIDENCES:
        errors.append(
            f"Rule {rule_id}: invalid confidence '{conf}'. "
            f"Must be one of {sorted(VALID_CONFIDENCES)}"
        )

    # Pattern
    pattern = data.get("pattern", {})
    if isinstance(pattern, dict):
        ptype = pattern.get("type", "")
        if ptype and ptype not in VALID_PATTERN_TYPES:
            errors.append(
                f"Rule {rule_id}: invalid pattern type '{ptype}'. "
                f"Must be one of {sorted(VALID_PATTERN_TYPES)}"
            )
        if ptype == "function_call" and not pattern.get("name") and not pattern.get("names"):
            errors.append(
                f"Rule {rule_id}: function_call pattern requires 'name' or 'names'"
            )

    # Languages
    languages = data.get("languages", [])
    if languages:
        for lang in languages:
            if lang.lower() not in VALID_LANGUAGES:
                errors.append(
                    f"Rule {rule_id}: unsupported language '{lang}'. "
                    f"Supported: {sorted(VALID_LANGUAGES)}"
                )

    return errors


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _parse_pattern(data: Dict[str, Any]) -> RulePattern:
    """Parse a pattern dictionary into a RulePattern."""
    return RulePattern(
        type=data.get("type", "function_call"),
        name=data.get("name"),
        names=data.get("names"),
        regex=data.get("regex"),
    )


def _parse_rule(data: Dict[str, Any], source_file: Optional[str] = None) -> Rule:
    """Parse a rule dictionary into a Rule object."""
    pattern_data = data.get("pattern", {})
    return Rule(
        id=data["id"],
        name=data["name"],
        severity=data["severity"].lower(),
        message=data["message"],
        pattern=_parse_pattern(pattern_data),
        confidence=data.get("confidence", "medium").lower(),
        languages=[lang.lower() for lang in data.get("languages", ["python"])],
        cwe=data.get("cwe"),
        references=data.get("references", []),
        category=data.get("category", "general"),
        enabled=data.get("enabled", True),
        tags=data.get("tags", []),
        source_file=source_file,
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_rules_from_file(path: str, strict: bool = False) -> List[Rule]:
    """Load rules from a single YAML file.

    Args:
        path: Path to the YAML rule file.
        strict: If True, raise on validation errors. If False, skip invalid rules.

    Returns:
        List of parsed Rule objects.
    """
    rules: List[Rule] = []
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        msg = f"Failed to parse YAML rule file {path}: {exc}"
        if strict:
            raise RuleValidationError(msg) from exc
        logger.warning(msg)
        return []
    except OSError as exc:
        msg = f"Failed to read rule file {path}: {exc}"
        if strict:
            raise RuleValidationError(msg) from exc
        logger.warning(msg)
        return []

    if not isinstance(data, dict) or "rules" not in data:
        msg = f"Rule file {path} must contain a top-level 'rules' key"
        if strict:
            raise RuleValidationError(msg)
        logger.warning(msg)
        return []

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        msg = f"'rules' in {path} must be a list"
        if strict:
            raise RuleValidationError(msg)
        logger.warning(msg)
        return []

    for i, rule_data in enumerate(raw_rules):
        if not isinstance(rule_data, dict):
            logger.warning("Rule #%d in %s is not a dict, skipping", i + 1, path)
            continue

        errors = validate_rule_dict(rule_data, source=path)
        if errors:
            for err in errors:
                if strict:
                    raise RuleValidationError(err)
                logger.warning(err)
            continue

        try:
            rule = _parse_rule(rule_data, source_file=path)
            if rule.enabled:
                rules.append(rule)
                logger.debug("Loaded rule %s from %s", rule.id, path)
            else:
                logger.debug("Skipping disabled rule %s from %s", rule.id, path)
        except (KeyError, TypeError) as exc:
            msg = f"Failed to parse rule #{i + 1} in {path}: {exc}"
            if strict:
                raise RuleValidationError(msg) from exc
            logger.warning(msg)

    return rules


def load_rules_from_directory(directory: str, strict: bool = False) -> List[Rule]:
    """Load all rules from YAML files in a directory (non-recursive).

    Args:
        directory: Path to the rules directory.
        strict: If True, raise on validation errors.

    Returns:
        List of parsed Rule objects.
    """
    rules: List[Rule] = []
    if not os.path.isdir(directory):
        logger.debug("Rules directory not found: %s", directory)
        return []

    for filename in sorted(os.listdir(directory)):
        if filename.endswith((".yml", ".yaml")):
            filepath = os.path.join(directory, filename)
            rules.extend(load_rules_from_file(filepath, strict=strict))

    logger.info("Loaded %d rules from %s", len(rules), directory)
    return rules


def load_all_rules(
    extra_dirs: Optional[Sequence[str]] = None,
    strict: bool = False,
) -> List[Rule]:
    """Load built-in rules and any user-specified rule directories.

    Args:
        extra_dirs: Additional directories to load rules from.
        strict: If True, raise on validation errors.

    Returns:
        Combined list of all rules, with user rules taking precedence
        (by rule ID) over built-in rules.
    """
    builtin_dir = os.path.abspath(BUILTIN_RULES_DIR)
    builtin_rules = load_rules_from_directory(builtin_dir, strict=strict)

    user_rules: List[Rule] = []
    if extra_dirs:
        for d in extra_dirs:
            user_rules.extend(load_rules_from_directory(d, strict=strict))

    # User rules override built-in rules with the same ID
    rule_map: Dict[str, Rule] = {}
    for rule in builtin_rules:
        rule_map[rule.id] = rule
    for rule in user_rules:
        if rule.id in rule_map:
            logger.info("User rule %s overrides built-in rule", rule.id)
        rule_map[rule.id] = rule

    all_rules = list(rule_map.values())
    logger.info("Total rules loaded: %d (%d built-in, %d user)", len(all_rules), len(builtin_rules), len(user_rules))
    return all_rules


# ---------------------------------------------------------------------------
# Rule index for fast lookup
# ---------------------------------------------------------------------------


class RuleIndex:
    """Indexed collection of rules for efficient matching.

    Provides O(1) lookup for function-call-based rules.
    """

    def __init__(self, rules: List[Rule]) -> None:
        self._rules = rules
        self._func_call_rules: Dict[str, List[Rule]] = {}
        self._all_func_names: Set[str] = set()

        for rule in rules:
            if rule.pattern.type == "function_call":
                for name in rule.pattern.get_all_names():
                    self._func_call_rules.setdefault(name, []).append(rule)
                    self._all_func_names.add(name)

    @property
    def rules(self) -> List[Rule]:
        """All rules in the index."""
        return self._rules

    @property
    def function_names(self) -> Set[str]:
        """All function names that trigger rules."""
        return self._all_func_names

    def match_function_call(self, func_name: str, language: str = "python") -> List[Rule]:
        """Find all rules matching a given function call.

        Args:
            func_name: The fully-qualified function name.
            language: The source language.

        Returns:
            List of matching rules.
        """
        candidates = self._func_call_rules.get(func_name, [])
        return [r for r in candidates if language in r.languages]

    def get_rules_by_language(self, language: str) -> List[Rule]:
        """Get all rules applicable to a given language."""
        return [r for r in self._rules if language in r.languages]

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Look up a rule by its ID."""
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def __len__(self) -> int:
        return len(self._rules)
