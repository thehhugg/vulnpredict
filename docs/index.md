# VulnPredict

**AI-powered vulnerability prediction for source code.**

VulnPredict combines static analysis, taint tracking, and machine learning to detect security vulnerabilities across multiple programming languages. It is designed for developers and security teams who want fast, accurate scanning integrated into their existing workflows.

## Supported Languages

| Language | Analyzer | Detection Rules |
|---|---|---|
| Python | AST-based + taint analysis | SQL injection, XSS, command injection, deserialization, SSRF, crypto, and more |
| JavaScript | Regex + pattern matching | DOM XSS, prototype pollution, eval injection, insecure dependencies |
| TypeScript/TSX | Extended JS analyzer | Same as JavaScript with TypeScript-specific patterns |
| Go | Regex-based pattern matching | SQL injection, command injection, weak crypto, insecure TLS, race conditions |
| IaC (Terraform, Dockerfile, K8s) | Config analysis | Misconfigurations, exposed ports, privilege escalation, missing security controls |

## Key Features

VulnPredict provides a comprehensive set of features for vulnerability detection and management. The **configurable rule engine** allows teams to define custom YAML-based detection rules alongside the built-in rule sets. **Scan profiles** (quick, standard, deep) let users balance speed and thoroughness depending on the context. The tool supports multiple **output formats** including JSON, SARIF, HTML, and Markdown, making it easy to integrate with CI/CD pipelines, GitHub code scanning, and pull request reviews.

The **baseline comparison** feature enables teams to track only new vulnerabilities introduced since a previous scan, which is essential for incremental adoption. A **secrets detector** identifies hardcoded credentials, API keys, and tokens across all supported languages. The **FastAPI dashboard API** stores scan results in SQLite and provides REST endpoints for querying findings, filtering by severity, and viewing aggregate statistics.

## Quick Start

```bash
pip install vulnpredict
vulnpredict scan /path/to/project
```

See the [Installation](getting-started/installation.md) and [Quick Start](getting-started/quickstart.md) guides for detailed setup instructions.
