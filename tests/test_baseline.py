"""Tests for baseline scanning features: fuzzy matching, save_baseline, --save-baseline CLI."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import pytest

from vulnpredict.suppression import (
    _finding_fingerprint,
    _finding_fuzzy_key,
    filter_by_baseline,
    load_baseline,
    save_baseline,
)


# ---------------------------------------------------------------------------
# Fuzzy key tests
# ---------------------------------------------------------------------------


class TestFuzzyKey:
    """Tests for _finding_fuzzy_key."""

    def test_basic_key(self) -> None:
        finding = {
            "file": "app.py",
            "line": 10,
            "rule_id": "VP-PY-001",
            "message": "Dangerous call",
        }
        key = _finding_fuzzy_key(finding)
        assert key == ("app.py", "VP-PY-001", "Dangerous call")

    def test_key_ignores_line(self) -> None:
        f1 = {"file": "app.py", "line": 10, "rule_id": "VP-PY-001", "message": "msg"}
        f2 = {"file": "app.py", "line": 15, "rule_id": "VP-PY-001", "message": "msg"}
        assert _finding_fuzzy_key(f1) == _finding_fuzzy_key(f2)

    def test_key_differs_by_file(self) -> None:
        f1 = {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"}
        f2 = {"file": "b.py", "line": 10, "rule_id": "R1", "message": "msg"}
        assert _finding_fuzzy_key(f1) != _finding_fuzzy_key(f2)

    def test_key_differs_by_rule(self) -> None:
        f1 = {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"}
        f2 = {"file": "a.py", "line": 10, "rule_id": "R2", "message": "msg"}
        assert _finding_fuzzy_key(f1) != _finding_fuzzy_key(f2)

    def test_falls_back_to_type(self) -> None:
        finding = {"file": "a.py", "line": 10, "type": "dangerous_call", "message": "m"}
        key = _finding_fuzzy_key(finding)
        assert key[1] == "dangerous_call"


# ---------------------------------------------------------------------------
# Fuzzy baseline matching tests
# ---------------------------------------------------------------------------


class TestFuzzyBaselineMatching:
    """Tests for fuzzy line matching in filter_by_baseline."""

    def test_exact_match(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 0
        assert len(known) == 1

    def test_fuzzy_match_line_shifted_up(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 13, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 0
        assert len(known) == 1

    def test_fuzzy_match_line_shifted_down(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 7, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 0
        assert len(known) == 1

    def test_fuzzy_match_at_boundary(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 15, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 0
        assert len(known) == 1

    def test_fuzzy_match_beyond_boundary(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 16, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 1
        assert len(known) == 0

    def test_fuzzy_match_different_file(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "b.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 1
        assert len(known) == 0

    def test_custom_fuzzy_lines(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        findings = [
            {"file": "a.py", "line": 20, "rule_id": "R1", "message": "msg"},
        ]
        # Default tolerance (5) should not match
        new, known = filter_by_baseline(findings, baseline, fuzzy_lines=5)
        assert len(new) == 1

        # Larger tolerance should match
        new, known = filter_by_baseline(findings, baseline, fuzzy_lines=10)
        assert len(known) == 1

    def test_mixed_new_and_known(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg1"},
            {"file": "b.py", "line": 20, "rule_id": "R2", "message": "msg2"},
        ]
        findings = [
            {"file": "a.py", "line": 12, "rule_id": "R1", "message": "msg1"},  # fuzzy match
            {"file": "c.py", "line": 5, "rule_id": "R3", "message": "msg3"},   # new
            {"file": "b.py", "line": 20, "rule_id": "R2", "message": "msg2"},  # exact match
        ]
        new, known = filter_by_baseline(findings, baseline)
        assert len(new) == 1
        assert len(known) == 2
        assert new[0]["file"] == "c.py"

    def test_empty_baseline(self) -> None:
        findings = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline(findings, [])
        assert len(new) == 1
        assert len(known) == 0

    def test_empty_findings(self) -> None:
        baseline = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg"},
        ]
        new, known = filter_by_baseline([], baseline)
        assert len(new) == 0
        assert len(known) == 0


# ---------------------------------------------------------------------------
# save_baseline tests
# ---------------------------------------------------------------------------


class TestSaveBaseline:
    """Tests for the save_baseline function."""

    def test_save_and_load_roundtrip(self, tmp_path: Any) -> None:
        findings = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg1"},
            {"file": "b.py", "line": 20, "rule_id": "R2", "message": "msg2"},
        ]
        baseline_path = str(tmp_path / "baseline.json")
        save_baseline(findings, baseline_path, scan_path="/test")

        # Verify file exists and is valid JSON
        assert os.path.exists(baseline_path)
        with open(baseline_path) as f:
            data = json.load(f)

        assert "findings" in data
        assert len(data["findings"]) == 2

    def test_load_saved_baseline(self, tmp_path: Any) -> None:
        findings = [
            {"file": "a.py", "line": 10, "rule_id": "R1", "message": "msg1"},
        ]
        baseline_path = str(tmp_path / "baseline.json")
        save_baseline(findings, baseline_path, scan_path="/test")

        loaded = load_baseline(baseline_path)
        assert len(loaded) == 1

    def test_save_empty_findings(self, tmp_path: Any) -> None:
        baseline_path = str(tmp_path / "baseline.json")
        save_baseline([], baseline_path)

        loaded = load_baseline(baseline_path)
        assert len(loaded) == 0

    def test_save_includes_metadata(self, tmp_path: Any) -> None:
        baseline_path = str(tmp_path / "baseline.json")
        save_baseline(
            [{"file": "a.py", "line": 1, "rule_id": "R1", "message": "m"}],
            baseline_path,
            scan_path="/project",
            scan_duration=1.5,
            file_count=42,
        )

        with open(baseline_path) as f:
            data = json.load(f)

        assert data["metadata"]["scan_path"] == "/project"
        assert data["metadata"]["scan_duration_seconds"] == 1.5
        assert data["metadata"]["files_scanned"] == 42

    def test_roundtrip_baseline_filtering(self, tmp_path: Any) -> None:
        """Save a baseline, load it, and use it for filtering.

        Note: save_baseline uses the JSON formatter which normalizes findings.
        The normalized format uses 'type' instead of 'rule_id' and may alter
        the 'message' field. So the current findings must match the normalized
        format for exact matching to work.
        """
        original_findings = [
            {"file": "a.py", "line": 10, "type": "dangerous_function", "message": "msg1"},
            {"file": "b.py", "line": 20, "type": "taint_analysis", "message": "msg2"},
        ]
        baseline_path = str(tmp_path / "baseline.json")
        save_baseline(original_findings, baseline_path)

        loaded = load_baseline(baseline_path)

        # The loaded findings are normalized; match against them
        # Use the same file/line/type/message as the loaded findings
        current_findings = [
            loaded[0].copy(),  # known (exact match)
            {"file": "c.py", "line": 5, "type": "new_type", "message": "new"},  # new
        ]
        new, known = filter_by_baseline(current_findings, loaded)
        assert len(new) == 1
        assert len(known) == 1
        assert new[0]["file"] == "c.py"
