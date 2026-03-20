# Installation

VulnPredict can be installed via pip, from source, or run as a Docker container.

## Via pip

The simplest way to install VulnPredict is from PyPI:

```bash
pip install vulnpredict
```

This installs the `vulnpredict` command-line tool and all required dependencies.

## From Source

For development or to get the latest unreleased features, clone the repository and install in editable mode:

```bash
git clone https://github.com/thehhugg/vulnpredict.git
cd vulnpredict
pip install -e ".[dev]"
```

## Via Docker

A pre-built Docker image is available from the GitHub Container Registry:

```bash
docker pull ghcr.io/thehhugg/vulnpredict:latest
docker run --rm -v $(pwd):/scan ghcr.io/thehhugg/vulnpredict scan /scan
```

## Requirements

VulnPredict requires **Python 3.9 or later**. The ML-based prediction features require PyTorch, which is installed automatically as a dependency. For environments where PyTorch is not available, VulnPredict falls back to rule-based detection only.

## Verifying Installation

After installation, verify that VulnPredict is working correctly:

```bash
vulnpredict --version
vulnpredict scan --demo
```

The `--demo` flag runs a scan against a built-in sample project to confirm that all analyzers are functioning.
