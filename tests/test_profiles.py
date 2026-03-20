"""Unit tests for scan profiles (vulnpredict.profiles)."""

from __future__ import annotations

import pytest

from vulnpredict.profiles import (
    PROFILES,
    VALID_PROFILES,
    ScanProfile,
    get_profile,
)


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------


class TestScanProfile:
    """Tests for the ScanProfile dataclass."""

    def test_quick_profile_settings(self) -> None:
        p = PROFILES["quick"]
        assert p.name == "quick"
        assert p.pattern_matching is True
        assert p.taint_analysis is False
        assert p.interprocedural_analysis is False
        assert p.dependency_check is False
        assert p.ml_scoring is False
        assert p.js_analysis is True

    def test_standard_profile_settings(self) -> None:
        p = PROFILES["standard"]
        assert p.name == "standard"
        assert p.pattern_matching is True
        assert p.taint_analysis is True
        assert p.interprocedural_analysis is True
        assert p.dependency_check is True
        assert p.ml_scoring is False
        assert p.js_analysis is True

    def test_deep_profile_settings(self) -> None:
        p = PROFILES["deep"]
        assert p.name == "deep"
        assert p.pattern_matching is True
        assert p.taint_analysis is True
        assert p.interprocedural_analysis is True
        assert p.dependency_check is True
        assert p.ml_scoring is True
        assert p.js_analysis is True

    def test_all_valid_profiles_exist(self) -> None:
        for name in VALID_PROFILES:
            assert name in PROFILES

    def test_profile_description(self) -> None:
        for name in VALID_PROFILES:
            desc = PROFILES[name].description
            assert isinstance(desc, str)
            assert len(desc) > 10

    def test_profile_is_frozen(self) -> None:
        p = PROFILES["quick"]
        with pytest.raises(AttributeError):
            p.ml_scoring = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# get_profile tests
# ---------------------------------------------------------------------------


class TestGetProfile:
    """Tests for the get_profile function."""

    def test_default_is_standard(self) -> None:
        p = get_profile()
        assert p.name == "standard"

    def test_none_returns_standard(self) -> None:
        p = get_profile(None)
        assert p.name == "standard"

    def test_quick(self) -> None:
        p = get_profile("quick")
        assert p.name == "quick"

    def test_standard(self) -> None:
        p = get_profile("standard")
        assert p.name == "standard"

    def test_deep(self) -> None:
        p = get_profile("deep")
        assert p.name == "deep"

    def test_case_insensitive(self) -> None:
        assert get_profile("QUICK").name == "quick"
        assert get_profile("Deep").name == "deep"
        assert get_profile("STANDARD").name == "standard"

    def test_invalid_profile_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown scan profile"):
            get_profile("turbo")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            get_profile("")


# ---------------------------------------------------------------------------
# Profile feature matrix
# ---------------------------------------------------------------------------


class TestProfileFeatureMatrix:
    """Verify the feature matrix from the issue description."""

    def test_quick_excludes_ml(self) -> None:
        assert not PROFILES["quick"].ml_scoring

    def test_quick_excludes_taint(self) -> None:
        assert not PROFILES["quick"].taint_analysis

    def test_quick_excludes_interprocedural(self) -> None:
        assert not PROFILES["quick"].interprocedural_analysis

    def test_quick_excludes_dependency(self) -> None:
        assert not PROFILES["quick"].dependency_check

    def test_standard_includes_taint(self) -> None:
        assert PROFILES["standard"].taint_analysis

    def test_standard_includes_dependency(self) -> None:
        assert PROFILES["standard"].dependency_check

    def test_standard_excludes_ml(self) -> None:
        assert not PROFILES["standard"].ml_scoring

    def test_deep_includes_everything(self) -> None:
        p = PROFILES["deep"]
        assert p.pattern_matching
        assert p.taint_analysis
        assert p.interprocedural_analysis
        assert p.dependency_check
        assert p.ml_scoring
        assert p.js_analysis
