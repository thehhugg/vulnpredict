# Development Setup

This guide covers setting up a development environment for contributing to VulnPredict.

## Prerequisites

VulnPredict development requires Python 3.9 or later and Git. A virtual environment is recommended.

## Clone and Install

```bash
git clone https://github.com/thehhugg/vulnpredict.git
cd vulnpredict
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The `[dev]` extra installs testing and linting dependencies including pytest, mypy, flake8, and coverage.

## Running Tests

The test suite uses pytest with coverage reporting:

```bash
pytest tests/
```

To run a specific test file:

```bash
pytest tests/test_py_analyzer.py -v
```

## Type Checking

VulnPredict uses mypy for static type checking. All public functions have type annotations:

```bash
mypy src/vulnpredict/
```

## Code Style

The project follows PEP 8 with a maximum line length of 100 characters. Use flake8 to check:

```bash
flake8 src/vulnpredict/
```

## Project Structure

The project uses the standard Python `src/` layout:

```
vulnpredict/
  src/vulnpredict/       # Main package
    cli.py               # Click-based CLI
    py_analyzer.py       # Python AST analyzer
    js_analyzer.py       # JavaScript analyzer
    go_analyzer.py       # Go analyzer
    iac_analyzer.py      # IaC analyzer
    secrets_detector.py  # Secrets detection
    ml.py                # ML pipeline
    rules.py             # YAML rule engine
    dashboard/           # FastAPI backend
    formatters/          # Output formatters
  tests/                 # Test suite
  rules/                 # Built-in YAML rules
  docs/                  # Documentation (MkDocs)
  demo_project/          # Sample vulnerable project
```

## Pull Request Process

All changes should be submitted as pull requests against the `master` branch. Each PR should include tests for new functionality and pass the full test suite. The CI pipeline runs tests, type checking, and linting automatically.
