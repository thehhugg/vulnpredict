# Changelog

All notable changes to VulnPredict will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Issue and PR templates: bug report, feature request, false positive/negative reports (#17)
- Comprehensive unit tests for JavaScript analyzer with 100% coverage (#10)
- Code coverage tracking with pytest-cov and Codecov integration (#6)
- SECURITY.md with vulnerability disclosure policy (#16)
- Pre-commit hooks: black, isort, flake8, bandit, detect-secrets (#5)
- Comprehensive GitHub Actions CI workflow with matrix testing (#4)
- Comprehensive unit tests for Python analyzer with 89% coverage (#9)

### Changed

- Reformatted all Python files with black and isort
- Updated CONTRIBUTING.md with development setup and pre-commit guide

### Removed

- Replaced legacy `python-app.yml` CI workflow with new `ci.yml`

## [0.1.0] - 2025-01-01

### Added

- Initial release of VulnPredict
- Python analyzer with AST-based vulnerability detection (eval/exec, hardcoded secrets, subprocess injection, SQL injection)
- JavaScript analyzer with esprima-based dangerous call detection (eval, Function, setTimeout, setInterval)
- Interprocedural taint analysis for Python
- Basic ML pipeline with feature extraction and scikit-learn model training
- NVD data ingestion for vulnerability pattern extraction
- CLI interface with `scan`, `train`, and `ingest` commands
- Demo project with example vulnerable Python and JavaScript files
- ESLint integration for JavaScript linting
- Bandit integration for Python security linting
- Git churn feature extraction for ML model

[Unreleased]: https://github.com/thehhugg/vulnpredict/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/thehhugg/vulnpredict/releases/tag/v0.1.0
