"""Scan profiles for VulnPredict.

Profiles control which analyzers and features are enabled during a scan,
allowing users to trade off between speed and thoroughness.

Three built-in profiles are provided:

- **quick**: Pattern matching only. No ML, no dependency checks, no
  interprocedural analysis. Ideal for pre-commit hooks and IDE integration.
- **standard** (default): Pattern matching, taint analysis, and dependency
  checks. Suitable for PR checks.
- **deep**: Everything in standard plus ML scoring and full interprocedural
  analysis. Suitable for nightly/release scans.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Profile definition
# ---------------------------------------------------------------------------

VALID_PROFILES = {"quick", "standard", "deep"}


@dataclass(frozen=True)
class ScanProfile:
    """Configuration for a scan profile."""

    name: str
    pattern_matching: bool = True
    taint_analysis: bool = True
    interprocedural_analysis: bool = True
    dependency_check: bool = True
    ml_scoring: bool = True
    js_analysis: bool = True

    @property
    def description(self) -> str:
        """Human-readable description of the profile."""
        return _DESCRIPTIONS.get(self.name, f"Custom profile: {self.name}")


_DESCRIPTIONS: Dict[str, str] = {
    "quick": "Pattern matching only — fastest, ideal for pre-commit hooks",
    "standard": "Pattern matching + taint analysis + dependency checks — balanced for PR checks",
    "deep": "Full analysis including ML scoring and interprocedural analysis — thorough for releases",
}

# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        pattern_matching=True,
        taint_analysis=False,
        interprocedural_analysis=False,
        dependency_check=False,
        ml_scoring=False,
        js_analysis=True,
    ),
    "standard": ScanProfile(
        name="standard",
        pattern_matching=True,
        taint_analysis=True,
        interprocedural_analysis=True,
        dependency_check=True,
        ml_scoring=False,
        js_analysis=True,
    ),
    "deep": ScanProfile(
        name="deep",
        pattern_matching=True,
        taint_analysis=True,
        interprocedural_analysis=True,
        dependency_check=True,
        ml_scoring=True,
        js_analysis=True,
    ),
}


def get_profile(name: Optional[str] = None) -> ScanProfile:
    """Return the scan profile for the given name.

    Args:
        name: Profile name (quick, standard, deep). Defaults to "standard".

    Returns:
        The corresponding ScanProfile.

    Raises:
        ValueError: If the profile name is not recognized.
    """
    if name is None:
        name = "standard"
    name = name.lower()
    if name not in PROFILES:
        raise ValueError(
            f"Unknown scan profile '{name}'. "
            f"Valid profiles: {', '.join(sorted(PROFILES))}"
        )
    return PROFILES[name]
