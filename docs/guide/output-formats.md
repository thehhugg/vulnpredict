# Output Formats

VulnPredict supports multiple output formats to integrate with different tools and workflows.

## JSON

The JSON format provides structured, machine-readable output suitable for programmatic processing:

```bash
vulnpredict scan /path/to/project --format json --output results.json
```

The JSON output includes a metadata section with scan information and an array of findings, each containing the file path, line number, severity, CWE identifier, and description.

## SARIF

SARIF (Static Analysis Results Interchange Format) is the industry standard for static analysis tools. It integrates directly with GitHub Code Scanning:

```bash
vulnpredict scan /path/to/project --format sarif --output results.sarif
```

Upload SARIF results to GitHub Code Scanning in your CI workflow:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Markdown

The Markdown format produces a summary suitable for pull request comments and reports:

```bash
vulnpredict scan /path/to/project --format markdown --output report.md
```

The Markdown output includes a severity summary table, a detailed findings table, and remediation guidance.

## HTML

The HTML format generates a self-contained report with styling and interactive elements:

```bash
vulnpredict scan /path/to/project --format html --output report.html
```

## Console (Default)

When no format is specified, VulnPredict prints a human-readable summary to the terminal with color-coded severity levels.
