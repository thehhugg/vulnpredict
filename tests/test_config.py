"""Tests for vulnpredict.config — project configuration loader."""

import os
import textwrap

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_dir(tmp_path):
    """Return a temporary directory for config file tests."""
    return tmp_path


@pytest.fixture
def write_config(config_dir):
    """Helper to write a .vulnpredict.yml in the temp dir."""
    def _write(content: str) -> str:
        path = config_dir / ".vulnpredict.yml"
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        return str(config_dir)
    return _write


# ---------------------------------------------------------------------------
# find_config_file
# ---------------------------------------------------------------------------

class TestFindConfigFile:
    def test_finds_existing_config(self, write_config):
        project_dir = write_config("version: 1\n")
        from vulnpredict.config import find_config_file
        result = find_config_file(project_dir)
        assert result is not None
        assert result.endswith(".vulnpredict.yml")

    def test_returns_none_when_missing(self, config_dir):
        from vulnpredict.config import find_config_file
        result = find_config_file(str(config_dir))
        assert result is None


# ---------------------------------------------------------------------------
# _load_yaml
# ---------------------------------------------------------------------------

class TestLoadYaml:
    def test_loads_valid_yaml(self, write_config):
        project_dir = write_config("""\
            version: 1
            scan:
              paths:
                - src/
        """)
        from vulnpredict.config import _load_yaml
        data = _load_yaml(os.path.join(project_dir, ".vulnpredict.yml"))
        assert data["version"] == 1
        assert data["scan"]["paths"] == ["src/"]

    def test_returns_empty_on_missing_file(self, config_dir):
        from vulnpredict.config import _load_yaml
        data = _load_yaml(os.path.join(str(config_dir), "nonexistent.yml"))
        assert data == {}

    def test_returns_empty_on_invalid_yaml(self, config_dir):
        bad_file = config_dir / ".vulnpredict.yml"
        bad_file.write_text("{{invalid: yaml: [", encoding="utf-8")
        from vulnpredict.config import _load_yaml
        data = _load_yaml(str(bad_file))
        assert data == {}

    def test_returns_empty_on_non_dict(self, config_dir):
        bad_file = config_dir / ".vulnpredict.yml"
        bad_file.write_text("- just\n- a\n- list\n", encoding="utf-8")
        from vulnpredict.config import _load_yaml
        data = _load_yaml(str(bad_file))
        assert data == {}


# ---------------------------------------------------------------------------
# _validate_config
# ---------------------------------------------------------------------------

class TestValidateConfig:
    def test_valid_config_no_warnings(self):
        from vulnpredict.config import _validate_config
        raw = {
            "version": 1,
            "scan": {"languages": ["python"]},
            "severity": {"minimum": "medium"},
            "output": {"format": "json"},
        }
        warnings = _validate_config(raw, "test.yml")
        assert warnings == []

    def test_warns_on_unsupported_version(self):
        from vulnpredict.config import _validate_config
        raw = {"version": 99}
        warnings = _validate_config(raw, "test.yml")
        assert len(warnings) == 1
        assert "99" in warnings[0]

    def test_warns_on_unsupported_language(self):
        from vulnpredict.config import _validate_config
        raw = {"scan": {"languages": ["python", "rust"]}}
        warnings = _validate_config(raw, "test.yml")
        assert len(warnings) == 1
        assert "rust" in warnings[0]

    def test_warns_on_invalid_severity(self):
        from vulnpredict.config import _validate_config
        raw = {"severity": {"minimum": "critical"}}
        warnings = _validate_config(raw, "test.yml")
        assert len(warnings) == 1
        assert "critical" in warnings[0]

    def test_warns_on_invalid_format(self):
        from vulnpredict.config import _validate_config
        raw = {"output": {"format": "xml"}}
        warnings = _validate_config(raw, "test.yml")
        assert len(warnings) == 1
        assert "xml" in warnings[0]


# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------

class TestDeepMerge:
    def test_simple_override(self):
        from vulnpredict.config import _deep_merge
        base = {"a": 1, "b": 2}
        override = {"b": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3}

    def test_nested_merge(self):
        from vulnpredict.config import _deep_merge
        base = {"scan": {"paths": ["."], "exclude": []}}
        override = {"scan": {"paths": ["src/"]}}
        result = _deep_merge(base, override)
        assert result["scan"]["paths"] == ["src/"]
        assert result["scan"]["exclude"] == []

    def test_new_keys_added(self):
        from vulnpredict.config import _deep_merge
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_does_not_mutate_base(self):
        from vulnpredict.config import _deep_merge
        base = {"scan": {"paths": ["."]}}
        override = {"scan": {"paths": ["src/"]}}
        _deep_merge(base, override)
        assert base["scan"]["paths"] == ["."]


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_returns_defaults_when_no_file(self, config_dir):
        from vulnpredict.config import DEFAULT_CONFIG, load_config
        result = load_config(str(config_dir))
        assert result == DEFAULT_CONFIG

    def test_merges_file_with_defaults(self, write_config):
        project_dir = write_config("""\
            version: 1
            scan:
              paths:
                - src/
              exclude:
                - tests/
            severity:
              minimum: high
        """)
        from vulnpredict.config import load_config
        result = load_config(project_dir)
        assert result["scan"]["paths"] == ["src/"]
        assert result["scan"]["exclude"] == ["tests/"]
        assert result["severity"]["minimum"] == "high"
        # Defaults preserved for unspecified sections
        assert result["ml"]["enabled"] is True
        assert result["output"]["format"] == "text"

    def test_handles_empty_yaml(self, config_dir):
        empty_file = config_dir / ".vulnpredict.yml"
        empty_file.write_text("", encoding="utf-8")
        from vulnpredict.config import DEFAULT_CONFIG, load_config
        result = load_config(str(config_dir))
        assert result == DEFAULT_CONFIG


# ---------------------------------------------------------------------------
# config_to_scan_config
# ---------------------------------------------------------------------------

class TestConfigToScanConfig:
    def test_converts_full_config(self):
        from vulnpredict.config import config_to_scan_config
        raw = {
            "scan": {
                "paths": ["src/"],
                "exclude": ["tests/"],
                "languages": ["python"],
            },
            "rules": {
                "additional_dirs": ["rules/"],
                "disabled": ["VULN001"],
            },
            "severity": {"minimum": "high"},
            "ml": {"enabled": False, "model_path": "model.joblib"},
            "output": {"format": "sarif", "file": "out.sarif"},
        }
        sc = config_to_scan_config(raw, config_file="test.yml")
        assert sc.paths == ["src/"]
        assert sc.exclude == ["tests/"]
        assert sc.languages == ["python"]
        assert sc.additional_rule_dirs == ["rules/"]
        assert sc.disabled_rules == ["VULN001"]
        assert sc.minimum_severity == "high"
        assert sc.ml_enabled is False
        assert sc.model_path == "model.joblib"
        assert sc.output_format == "sarif"
        assert sc.output_file == "out.sarif"
        assert sc.config_file_used == "test.yml"

    def test_uses_defaults_for_missing_keys(self):
        from vulnpredict.config import config_to_scan_config
        sc = config_to_scan_config({})
        assert sc.paths == ["."]
        assert sc.languages == ["python", "javascript"]
        assert sc.minimum_severity == "low"
        assert sc.ml_enabled is True


# ---------------------------------------------------------------------------
# merge_cli_overrides
# ---------------------------------------------------------------------------

class TestMergeCliOverrides:
    def test_overrides_applied(self):
        from vulnpredict.config import ScanConfig, merge_cli_overrides
        sc = ScanConfig(output_format="text", minimum_severity="low")
        result = merge_cli_overrides(
            sc,
            output_format="json",
            minimum_severity="high",
        )
        assert result.output_format == "json"
        assert result.minimum_severity == "high"

    def test_none_values_not_applied(self):
        from vulnpredict.config import ScanConfig, merge_cli_overrides
        sc = ScanConfig(output_format="sarif", minimum_severity="medium")
        result = merge_cli_overrides(sc, output_format=None, minimum_severity=None)
        assert result.output_format == "sarif"
        assert result.minimum_severity == "medium"


# ---------------------------------------------------------------------------
# generate_default_config
# ---------------------------------------------------------------------------

class TestGenerateDefaultConfig:
    def test_returns_valid_yaml_string(self):
        from vulnpredict.config import generate_default_config
        content = generate_default_config()
        assert isinstance(content, str)
        assert "version: 1" in content
        assert "scan:" in content
        assert "severity:" in content
        assert "ml:" in content
        assert "output:" in content

    def test_parseable_as_yaml(self):
        import yaml
        from vulnpredict.config import generate_default_config
        content = generate_default_config()
        data = yaml.safe_load(content)
        assert isinstance(data, dict)
        assert data["version"] == 1


# ---------------------------------------------------------------------------
# CLI init command
# ---------------------------------------------------------------------------

class TestInitCommand:
    def test_creates_config_file(self, config_dir):
        from click.testing import CliRunner
        from vulnpredict.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(config_dir)])
        assert result.exit_code == 0
        assert "Created" in result.output
        config_path = config_dir / ".vulnpredict.yml"
        assert config_path.exists()
        content = config_path.read_text()
        assert "version: 1" in content

    def test_refuses_overwrite_without_confirm(self, config_dir):
        from click.testing import CliRunner
        from vulnpredict.cli import main
        # Create existing config
        (config_dir / ".vulnpredict.yml").write_text("version: 1\n")
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(config_dir)], input="n\n")
        assert "Aborted" in result.output

    def test_overwrites_with_confirm(self, config_dir):
        from click.testing import CliRunner
        from vulnpredict.cli import main
        (config_dir / ".vulnpredict.yml").write_text("old content\n")
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(config_dir)], input="y\n")
        assert result.exit_code == 0
        assert "Created" in result.output
        content = (config_dir / ".vulnpredict.yml").read_text()
        assert "version: 1" in content
