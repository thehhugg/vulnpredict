# VulnPredict

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Predictive Vulnerability Intelligence Tool**

VulnPredict combines static analysis and machine learning to find potential software vulnerabilities before they are publicly disclosed. It analyzes code patterns, tracks data flows, learns from historical CVE data, and highlights risky areas of a codebase.

> **Status:** Early development. Not yet published to PyPI or container registries. Install from source (see below).

## Features
- **Taint Analysis** &mdash; tracks untrusted data from sources to dangerous sinks, including across function boundaries.
- **Code Churn & Author Metrics** &mdash; uses git history to spot frequently changed, multi-author files.
- **Dependency Risk Analysis** &mdash; flags outdated or vulnerable packages via PyPI and OSV.dev.
- **Secrets Detection** &mdash; identifies passwords, tokens, API keys, and other sensitive data in source code.
- **Deep Code Embeddings** &mdash; CodeBERT-powered semantic understanding of code patterns.
- **NVD/CVE Pattern Mining** &mdash; extracts real-world vulnerability patterns for ML training.
- **Configurable Rules** &mdash; YAML-based custom rule engine for project-specific checks.
- **Scan Profiles** &mdash; quick, standard, and deep scan modes.
- **IaC Scanning** &mdash; Terraform, Dockerfile, and Kubernetes manifest analysis.
- **Multiple Output Formats** &mdash; terminal, JSON, SARIF, Markdown, and HTML reports.
- **Baseline Support** &mdash; suppress known findings with `--save-baseline` / `--baseline`.
- **Language Support** &mdash; Python, JavaScript, TypeScript, and Go.

## Installation

### From source (recommended for now)
```sh
git clone https://github.com/thehhugg/vulnpredict.git
cd vulnpredict
pip install -e .
```

JavaScript/TypeScript analysis additionally requires Node.js for `esprima` and optional ESLint integration.

### Docker (local build)
A Dockerfile is included but the image is not yet published to a registry. To build locally:
```sh
docker build -t vulnpredict .
docker run --rm -v $(pwd):/code vulnpredict scan /code
```

## Quickstart

Scan the included demo project to see VulnPredict in action:
```sh
# Generate labeled training data from the demo
python -m vulnpredict.generate_labeled_data demo_project labeled_findings.csv

# Train the ML model
python -m vulnpredict train labeled_findings.csv

# Scan and get predictions
python -m vulnpredict scan demo_project
```

## CLI Reference

The `vulnpredict` command provides these subcommands:

| Command | Description |
|---------|-------------|
| `vulnpredict scan PATH` | Analyze a codebase and print prioritized findings |
| `vulnpredict train CSV` | Train the ML model from labeled data |
| `vulnpredict fetch-nvd YEAR OUT` | Download CVE data from the NVD |
| `vulnpredict extract-nvd-patterns JSON OUT` | Extract vulnerability patterns from NVD data |

### Output options
```sh
vulnpredict scan /path/to/code --format json --output results.json
vulnpredict scan /path/to/code --format sarif --output results.sarif
vulnpredict scan /path/to/code --format markdown
vulnpredict scan /path/to/code --min-severity high
vulnpredict scan /path/to/code --profile deep
```

## Repository Layout
```
src/vulnpredict/       Source code (analyzers, ML pipeline, formatters)
tests/                 986 unit and integration tests
rules/                 YAML rule definitions
demo_project/          Sample vulnerable code for training and demos
docs/                  MkDocs documentation site
```

## ML Pipeline
1. **Feature Extraction** &mdash; static analysis, taint tracking, dependency risk, secrets detection, code embeddings, and CVE pattern features.
2. **Model Training** &mdash; scikit-learn Random Forest on labeled findings (extensible to other classifiers).
3. **Prediction** &mdash; scores new findings with a vulnerability likelihood based on all extracted features.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidance on adding analyzers, rules, or ML improvements.

## License
[MIT](LICENSE)
