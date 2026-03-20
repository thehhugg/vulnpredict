"""Project configuration loader for VulnPredict.

Reads ``.vulnpredict.yml`` from the project root and merges it with CLI
arguments.  CLI arguments always take precedence over file-based config.
"""

from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vulnpredict.config")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_FILENAME = ".vulnpredict.yml"
SUPPORTED_LANGUAGES = {"python", "javascript"}
SUPPORTED_FORMATS = {"text", "json", "sarif", "html"}
SUPPORTED_SEVERITIES = {"low", "medium", "high"}
CURRENT_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": CURRENT_SCHEMA_VERSION,
    "scan": {
        "paths": ["."],
        "exclude": [],
        "languages": ["python", "javascript"],
    },
    "rules": {
        "additional_dirs": [],
        "disabled": [],
    },
    "severity": {
        "minimum": "low",
    },
    "ml": {
        "enabled": True,
        "model_path": None,
    },
    "output": {
        "format": "text",
        "file": None,
    },
}


# ---------------------------------------------------------------------------
# Data class for typed access
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Typed representation of the resolved VulnPredict configuration."""

    # scan section
    paths: List[str] = field(default_factory=lambda: ["."])
    exclude: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=lambda: ["python", "javascript"])

    # rules section
    additional_rule_dirs: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)

    # severity section
    minimum_severity: str = "low"

    # ml section
    ml_enabled: bool = True
    model_path: Optional[str] = None

    # output section
    output_format: str = "text"
    output_file: Optional[str] = None

    # meta
    config_file_used: Optional[str] = None


# ---------------------------------------------------------------------------
# YAML loading helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: str) -> Dict[str, Any]:
    """Load a YAML file and return its contents as a dict.

    Returns an empty dict on any error (missing file, parse error, etc.).
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "PyYAML is not installed; cannot read %s. "
            "Install it with: pip install pyyaml",
            path,
        )
        return {}

    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                logger.warning("Config file %s does not contain a YAML mapping", path)
                return {}
            return data
    except FileNotFoundError:
        logger.debug("No config file found at %s", path)
        return {}
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse config file %s: %s", path, exc)
        return {}
    except OSError as exc:
        logger.warning("Could not read config file %s: %s", path, exc)
        return {}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_config(raw: Dict[str, Any], filepath: str) -> List[str]:
    """Validate a raw config dict and return a list of warning messages.

    Warnings are non-fatal; the loader will use defaults for invalid values.
    """
    warnings: List[str] = []

    # Version check
    version = raw.get("version")
    if version is not None and version != CURRENT_SCHEMA_VERSION:
        warnings.append(
            f"Config version {version} in {filepath} is not supported "
            f"(expected {CURRENT_SCHEMA_VERSION}). Some settings may be ignored."
        )

    # Scan section
    scan = raw.get("scan", {})
    if isinstance(scan, dict):
        langs = scan.get("languages", [])
        if isinstance(langs, list):
            for lang in langs:
                if lang not in SUPPORTED_LANGUAGES:
                    warnings.append(
                        f"Unsupported language '{lang}' in config. "
                        f"Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}"
                    )

    # Severity section
    severity = raw.get("severity", {})
    if isinstance(severity, dict):
        min_sev = severity.get("minimum")
        if min_sev and min_sev not in SUPPORTED_SEVERITIES:
            warnings.append(
                f"Invalid minimum severity '{min_sev}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_SEVERITIES))}"
            )

    # Output section
    output = raw.get("output", {})
    if isinstance(output, dict):
        fmt = output.get("format")
        if fmt and fmt not in SUPPORTED_FORMATS:
            warnings.append(
                f"Unsupported output format '{fmt}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}"
            )

    return warnings


# ---------------------------------------------------------------------------
# Deep merge
# ---------------------------------------------------------------------------


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict.

    - Dict values are merged recursively.
    - All other values in *override* replace those in *base*.
    - Keys in *base* not present in *override* are preserved.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_config_file(project_dir: str) -> Optional[str]:
    """Search for ``.vulnpredict.yml`` in *project_dir* and return its path.

    Returns ``None`` if no config file is found.
    """
    candidate = os.path.join(project_dir, CONFIG_FILENAME)
    if os.path.isfile(candidate):
        return candidate
    return None


def load_config(project_dir: str) -> Dict[str, Any]:
    """Load and validate the project configuration.

    1. Start with ``DEFAULT_CONFIG``.
    2. If ``.vulnpredict.yml`` exists in *project_dir*, merge it on top.
    3. Validate and log warnings for any issues.

    Returns the merged configuration dict.
    """
    merged = copy.deepcopy(DEFAULT_CONFIG)
    config_path = find_config_file(project_dir)

    if config_path is None:
        logger.debug("No %s found in %s; using defaults", CONFIG_FILENAME, project_dir)
        return merged

    raw = _load_yaml(config_path)
    if not raw:
        return merged

    # Validate
    warnings = _validate_config(raw, config_path)
    for w in warnings:
        logger.warning(w)

    merged = _deep_merge(merged, raw)
    logger.info("Loaded configuration from %s", config_path)
    return merged


def config_to_scan_config(
    config: Dict[str, Any],
    config_file: Optional[str] = None,
) -> ScanConfig:
    """Convert a raw config dict to a typed ``ScanConfig`` object."""
    scan = config.get("scan", {})
    rules = config.get("rules", {})
    severity = config.get("severity", {})
    ml = config.get("ml", {})
    output = config.get("output", {})

    return ScanConfig(
        paths=scan.get("paths", ["."]),
        exclude=scan.get("exclude", []),
        languages=scan.get("languages", ["python", "javascript"]),
        additional_rule_dirs=rules.get("additional_dirs", []),
        disabled_rules=rules.get("disabled", []),
        minimum_severity=severity.get("minimum", "low"),
        ml_enabled=ml.get("enabled", True),
        model_path=ml.get("model_path"),
        output_format=output.get("format", "text"),
        output_file=output.get("file"),
        config_file_used=config_file,
    )


def merge_cli_overrides(
    scan_config: ScanConfig,
    *,
    output_format: Optional[str] = None,
    output_file: Optional[str] = None,
    minimum_severity: Optional[str] = None,
    ml_enabled: Optional[bool] = None,
) -> ScanConfig:
    """Apply CLI argument overrides to a ``ScanConfig``.

    Only non-``None`` values override the file-based configuration.
    CLI always takes precedence.
    """
    if output_format is not None:
        scan_config.output_format = output_format
    if output_file is not None:
        scan_config.output_file = output_file
    if minimum_severity is not None:
        scan_config.minimum_severity = minimum_severity
    if ml_enabled is not None:
        scan_config.ml_enabled = ml_enabled
    return scan_config


def generate_default_config() -> str:
    """Return a default ``.vulnpredict.yml`` as a YAML string.

    This is used by the ``vulnpredict init`` command.
    """
    return """# VulnPredict Configuration
# Documentation: https://github.com/thehhugg/vulnpredict#configuration
version: 1

scan:
  # Directories to scan (relative to project root)
  paths:
    - .
  # Directories/files to exclude from scanning
  exclude:
    - tests/
    - docs/
    - node_modules/
    - .venv/
    - __pycache__/
  # Languages to analyze
  languages:
    - python
    - javascript

rules:
  # Additional directories containing custom rule files
  additional_dirs: []
  # Rule IDs to disable
  disabled: []

severity:
  # Minimum severity to report: low, medium, high
  minimum: low

ml:
  # Enable ML-based vulnerability prediction
  enabled: true
  # Path to a custom trained model (optional)
  # model_path: models/custom_model.joblib

output:
  # Output format: text, json, sarif, html
  format: text
  # Output file path (optional; defaults to stdout for text/json)
  # file: vulnpredict-results.sarif
"""
