# Scanning Projects

VulnPredict provides flexible scanning capabilities that can be tailored to different project types and workflows.

## Basic Scanning

The `scan` command accepts a directory path and recursively analyzes all supported source files:

```bash
vulnpredict scan /path/to/project
```

VulnPredict automatically detects and scans files with the following extensions:

| Extension | Analyzer |
|---|---|
| `.py` | Python AST analyzer + taint tracking |
| `.js`, `.jsx` | JavaScript pattern analyzer |
| `.ts`, `.tsx` | TypeScript analyzer |
| `.go` | Go security analyzer |
| `.tf` | Terraform IaC analyzer |
| `Dockerfile` | Dockerfile analyzer |
| `.yaml`, `.yml` | Kubernetes manifest analyzer |

## Custom Rules Directory

Load additional YAML-based detection rules from a directory:

```bash
vulnpredict scan /path/to/project --rules-dir /path/to/custom-rules
```

Custom rules are loaded alongside the built-in rules. See the [Rule Authoring](../rule-authoring.md) guide for the YAML rule format.

## Secrets Detection

VulnPredict includes a built-in secrets detector that identifies hardcoded credentials, API keys, and tokens. This runs automatically during every scan and covers patterns for AWS, GitHub, Slack, Stripe, SendGrid, and generic high-entropy strings.

## Exit Codes

The `scan` command uses exit codes to indicate the scan outcome, which is useful for CI/CD integration:

| Exit Code | Meaning |
|---|---|
| 0 | No findings (or all below threshold) |
| 1 | Findings detected above the minimum severity |
| 2 | Scan error (invalid path, configuration issue) |

## Pre-commit Integration

VulnPredict can be used as a pre-commit hook to catch vulnerabilities before they are committed. Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v1.0.0
    hooks:
      - id: vulnpredict
```
