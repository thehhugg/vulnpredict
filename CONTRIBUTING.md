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

## Extension Points

- **Language Analyzers:** Add new modules under `vulnpredict/` for additional language support.
- **Rules and Patterns:** Contribute new vulnerability patterns or detection rules as Python modules or JSON files.
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
