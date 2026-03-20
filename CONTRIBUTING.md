# Contributing to VulnPredict

Thank you for your interest in contributing! VulnPredict is an open source project and welcomes contributions from the community.

## Getting Started

### Prerequisites

- Python 3.9 or later
- Node.js 20+ (for the JavaScript analyzer)
- Git

### Development Setup

1. **Fork and clone** the repository:

   ```bash
   git clone https://github.com/<your-username>/vulnpredict.git
   cd vulnpredict
   ```

2. **Create a virtual environment** (recommended):

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install the package in editable mode** with development dependencies:

   ```bash
   pip install -e .
   pip install pytest pytest-cov black isort flake8
   ```

4. **Install pre-commit hooks** to enforce code quality automatically:

   ```bash
   pip install pre-commit
   pre-commit install
   ```

   After this, every `git commit` will automatically run formatting and linting checks. If any hook modifies a file (e.g., black reformats it), the commit will be aborted so you can review and re-stage the changes.

5. **Verify your setup** by running the test suite:

   ```bash
   pytest tests/ -v
   ```

## Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to maintain consistent code quality. The following hooks run automatically on every commit:

| Hook | Purpose |
|------|---------|
| `trailing-whitespace` | Removes trailing whitespace |
| `end-of-file-fixer` | Ensures files end with a newline |
| `check-yaml` | Validates YAML syntax |
| `check-added-large-files` | Prevents committing files larger than 500 KB |
| `check-merge-conflict` | Detects unresolved merge conflict markers |
| `debug-statements` | Catches leftover `breakpoint()` and `pdb` calls |
| `black` | Formats Python code (line length 120) |
| `isort` | Sorts imports (black-compatible profile) |
| `detect-secrets` | Prevents accidental credential or secret leakage |
| `bandit` | Security-focused linting for Python code |
| `flake8` | Lints Python code for errors and style issues |

### Running Hooks Manually

To run all hooks against every file (not just staged changes):

```bash
pre-commit run --all-files
```

To run a specific hook:

```bash
pre-commit run black --all-files
pre-commit run flake8 --all-files
```

To update hook versions to their latest releases:

```bash
pre-commit autoupdate
```

## How to Contribute

- **Bug Reports and Feature Requests:** Please use [GitHub Issues](https://github.com/thehhugg/vulnpredict/issues).
- **Code Contributions:**
  1. Fork the repository and create a new branch from `master`.
  2. Make your changes with clear, descriptive commit messages.
  3. Add or update tests as appropriate.
  4. Ensure all pre-commit hooks pass (`pre-commit run --all-files`).
  5. Submit a pull request describing your changes.

## Versioning Policy

VulnPredict follows [Semantic Versioning (SemVer)](https://semver.org/spec/v2.0.0.html):

| Version Component | When to Increment | Example |
|-------------------|-------------------|---------|
| **MAJOR** (X.0.0) | Breaking changes to CLI, output format, or public API | Removing a CLI flag, changing SARIF output schema |
| **MINOR** (0.X.0) | New features, new analyzers, new output formats (backward-compatible) | Adding Go analyzer, adding SARIF output |
| **PATCH** (0.0.X) | Bug fixes, documentation updates, test improvements | Fixing a false positive, updating docs |

Development versions use the `-dev` suffix (e.g., `0.2.0-dev`). When preparing a release, the `-dev` suffix is removed and the CHANGELOG is updated.

All notable changes must be documented in [CHANGELOG.md](CHANGELOG.md) following the [Keep a Changelog](https://keepachangelog.com/) format. When submitting a PR that adds a feature, fixes a bug, or introduces a breaking change, please add an entry under the `[Unreleased]` section.

## Project Architecture

VulnPredict uses the standard Python `src/` layout. The main package lives in `src/vulnpredict/` and the test suite is in `tests/`.

| Module | Responsibility |
|---|---|
| `cli.py` | Click-based CLI that orchestrates the scan pipeline |
| `py_analyzer.py` | Python AST analysis with taint tracking |
| `interprocedural_taint.py` | Cross-function taint propagation for Python |
| `js_analyzer.py` | JavaScript security analysis |
| `ts_analyzer.py` | TypeScript/TSX analysis (extends JS analyzer) |
| `go_analyzer.py` | Go security analysis with 15 detection rules |
| `iac_analyzer.py` | Terraform, Dockerfile, and Kubernetes analysis |
| `secrets_detector.py` | Hardcoded credential and API key detection |
| `rules.py` | YAML-based configurable rule engine |
| `ml.py` | ML model loading and vulnerability prediction |
| `severity.py` | Severity scoring and finding ranking |
| `suppression.py` | Baseline comparison and finding suppression |
| `profiles.py` | Scan profile definitions (quick, standard, deep) |
| `formatters/` | Output format implementations (JSON, SARIF, HTML, Markdown) |
| `dashboard/` | FastAPI REST API for scan result storage |

## Your First Contribution: Adding a Detection Rule

The easiest way to contribute is by adding a new YAML-based detection rule. Here is a complete walkthrough.

### Step 1: Create a Rule File

Create a new YAML file in the `rules/` directory:

```yaml
# rules/python-ssrf-advanced.yml
id: VP-CUSTOM-001
name: SSRF via urllib
language: python
severity: high
cwe: CWE-918
message: "Potential SSRF: urllib.request.urlopen called with user-controlled URL"
pattern: "urllib\\.request\\.urlopen\\s*\\("
```

### Step 2: Write a Test

Create a test in `tests/` that verifies your rule detects the vulnerability:

```python
from vulnpredict.rules import RuleEngine

def test_ssrf_rule(tmp_path):
    engine = RuleEngine()
    engine.load_rules_from_directory("rules/")
    rules = engine.get_rules(language="python")
    assert any(r["id"] == "VP-CUSTOM-001" for r in rules)
```

### Step 3: Test and Submit

```bash
pytest tests/test_custom_ssrf_rule.py -v
git checkout -b feature/ssrf-urllib-rule
git add rules/python-ssrf-advanced.yml tests/test_custom_ssrf_rule.py
git commit -m "feat: add SSRF detection rule for urllib.request.urlopen"
git push origin feature/ssrf-urllib-rule
```

Then open a pull request on GitHub.

## Areas Where Contributions Are Most Needed

**New detection rules.** Adding YAML-based rules for common vulnerability patterns is the easiest way to improve VulnPredict's coverage. Check the [CWE Top 25](https://cwe.mitre.org/top25/) for inspiration.

**Language analyzers.** Adding support for new languages (Java, C#, Ruby, PHP) would significantly expand the tool's usefulness.

**False positive reduction.** Improving the precision of existing rules by adding context-aware checks reduces noise for users.

**Documentation.** Improving guides, adding examples, and fixing typos are always welcome.

**Performance optimization.** Profiling and optimizing the scan pipeline for large codebases.

Look for issues labeled `good first issue` in the [issue tracker](https://github.com/thehhugg/vulnpredict/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for beginner-friendly tasks.

## Extension Points

- **Language Analyzers:** Add new modules under `src/vulnpredict/` for additional language support.
- **Rules and Patterns:** Contribute new vulnerability patterns as YAML rules in the `rules/` directory.
- **ML Models:** Submit improvements to model training, feature engineering, or evaluation.

## Code Style

- **Formatting:** [Black](https://github.com/psf/black) with a line length of 120 characters.
- **Import sorting:** [isort](https://github.com/pycqa/isort) with the `black` profile.
- **Linting:** [Flake8](https://github.com/pycqa/flake8) with `E203` and `W503` ignored for black compatibility.
- **Type hints:** Encouraged for all public functions and classes.
- **Documentation:** Document public functions and classes with docstrings.

## Community

- Be respectful and constructive in all communications.
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for more.
