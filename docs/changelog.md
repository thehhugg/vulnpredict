# Changelog

All notable changes to VulnPredict are documented in this file.

## v1.0.0 (Unreleased)

### Added

**Analysis Engine**

- Configurable YAML-based rule engine with built-in Python and JavaScript rule sets
- Scan profiles (quick, standard, deep) for controlling analysis depth
- Comprehensive secrets detection covering AWS, GitHub, Slack, Stripe, and generic patterns
- Baseline comparison with fuzzy line matching for tracking new vulnerabilities
- Expanded JavaScript analyzer with prototype pollution, SSRF, and CORS detection

**Language Support**

- TypeScript and TSX file scanning via extended JavaScript analyzer
- Go security analyzer with 15 detection rules (SQL injection, command injection, weak crypto, insecure TLS, race conditions)
- Infrastructure-as-Code scanning for Terraform, Dockerfile, and Kubernetes manifests

**Output and Integration**

- Markdown output format for pull request comments
- FastAPI dashboard API with SQLite storage, pagination, filtering, and API key authentication
- Pre-commit hook configuration for automated scanning

**Project Quality**

- Full type annotations with mypy strict mode (zero errors)
- CLI integration tests (39 tests)
- ML pipeline unit tests
- NVD data ingestion tests
- Restructured to Python `src/` layout
- MkDocs Material documentation site

### Changed

- Project layout migrated from flat to `src/` layout for packaging best practices
