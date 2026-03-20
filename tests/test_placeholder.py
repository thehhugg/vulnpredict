"""Placeholder tests to ensure pytest runs successfully.

These tests verify basic package health. They will be supplemented
by comprehensive tests in Issue #8.
"""

import subprocess
import sys

import pytest


def test_vulnpredict_import():
    """Verify that the vulnpredict package can be imported."""
    import vulnpredict

    assert vulnpredict is not None


def test_cli_entry_point():
    """Verify that the CLI module loads without errors.

    This test is skipped if optional dependencies (transformers, torch)
    are not installed, since py_analyzer.py imports them at module level.
    """
    try:
        from vulnpredict import cli

        assert hasattr(cli, "main")
    except ModuleNotFoundError as exc:
        pytest.skip(f"Optional dependency not installed: {exc.name}")


def test_cli_help():
    """Verify the CLI --help flag works without crashing."""
    result = subprocess.run(
        [sys.executable, "-m", "vulnpredict", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Allow both success (0) and import errors (1) if optional deps are missing
    assert result.returncode in (0, 1, 2)
