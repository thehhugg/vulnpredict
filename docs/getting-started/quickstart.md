# Quick Start

This guide walks through scanning a project for the first time and understanding the results.

## Scanning a Project

Point VulnPredict at any directory containing source code:

```bash
vulnpredict scan /path/to/your/project
```

VulnPredict automatically detects the languages present and applies the appropriate analyzers. By default, it uses the **standard** scan profile, which balances speed and thoroughness.

## Understanding the Output

The default output is a human-readable table printed to the terminal. Each finding includes the file path, line number, severity, vulnerability type, and a description of the issue.

To get machine-readable output, use the `--format` flag:

```bash
vulnpredict scan /path/to/project --format json
vulnpredict scan /path/to/project --format sarif
vulnpredict scan /path/to/project --format markdown
```

## Choosing a Scan Profile

VulnPredict offers three scan profiles that control the depth of analysis:

| Profile | Description | Use Case |
|---|---|---|
| `quick` | Pattern matching only, no ML | Pre-commit hooks, rapid feedback |
| `standard` | Pattern matching + taint analysis | Default for CI/CD pipelines |
| `deep` | Full analysis including ML prediction | Release audits, security reviews |

```bash
vulnpredict scan /path/to/project --profile quick
vulnpredict scan /path/to/project --profile deep
```

## Saving Results

Write results to a file using the `--output` flag:

```bash
vulnpredict scan /path/to/project --format json --output results.json
vulnpredict scan /path/to/project --format sarif --output results.sarif
```

## Filtering by Severity

Use the `--min-severity` flag to suppress lower-severity findings:

```bash
vulnpredict scan /path/to/project --min-severity high
```

## Next Steps

Explore the [User Guide](../guide/scanning.md) for advanced scanning options, or see [Rule Authoring](../rule-authoring.md) to create custom detection rules.
