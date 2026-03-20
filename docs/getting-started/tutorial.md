# Getting Started Tutorial

This tutorial walks you through your first VulnPredict scan in under five minutes. By the end, you will have scanned a project, understood the output, and set up automated scanning in GitHub Actions.

## Step 1: Install VulnPredict

=== "pip"

    ```bash
    pip install vulnpredict
    ```

=== "Docker"

    ```bash
    docker pull ghcr.io/thehhugg/vulnpredict:latest
    ```

=== "From Source"

    ```bash
    git clone https://github.com/thehhugg/vulnpredict.git
    cd vulnpredict
    pip install -e .
    ```

Verify the installation:

```bash
vulnpredict --version
```

## Step 2: Run the Demo Scan

VulnPredict ships with a built-in demo project containing intentional vulnerabilities. Run it to see the tool in action:

```bash
vulnpredict scan --demo
```

Expected output:

```
VulnPredict Scan Results
========================
Target: demo_project/
Files scanned: 8
Findings: 12

CRITICAL  app.py:42        SQL injection via string concatenation (CWE-89)
CRITICAL  app.py:67        Command injection via os.system() (CWE-78)
HIGH      views.py:15      Cross-site scripting in template rendering (CWE-79)
HIGH      config.py:3      Hardcoded database password (CWE-798)
MEDIUM    utils.py:28      Use of MD5 for password hashing (CWE-328)
...
```

Each finding includes the **severity level**, **file and line number**, a **description**, and the associated **CWE identifier**.

## Step 3: Scan Your Own Project

Point VulnPredict at your project directory:

```bash
vulnpredict scan /path/to/your/project
```

For Docker users:

```bash
docker run --rm -v $(pwd):/scan ghcr.io/thehhugg/vulnpredict scan /scan
```

## Step 4: Understanding the Output

### Severity Levels

VulnPredict classifies findings into four severity levels:

| Severity | Description | Action |
|---|---|---|
| **Critical** | Exploitable vulnerabilities that can lead to data breach or system compromise | Fix immediately |
| **High** | Serious security issues that should be addressed before release | Fix before merge |
| **Medium** | Potential security concerns that may require attention | Review and assess |
| **Low** | Minor issues or informational findings | Address when convenient |

### Output Formats

Save results in different formats depending on your workflow:

```bash
# JSON for programmatic processing
vulnpredict scan . --format json --output results.json

# SARIF for GitHub Code Scanning
vulnpredict scan . --format sarif --output results.sarif

# Markdown for pull request comments
vulnpredict scan . --format markdown --output report.md

# HTML for standalone reports
vulnpredict scan . --format html --output report.html
```

## Step 5: Set Up GitHub Actions

Create `.github/workflows/vulnpredict.yml` in your repository:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install VulnPredict
        run: pip install vulnpredict

      - name: Run security scan
        run: vulnpredict scan . --format sarif --output results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

This workflow runs VulnPredict on every push and pull request, and uploads the results to GitHub Code Scanning where they appear as annotations on the code.

## Step 6: Establish a Baseline

For existing projects with known findings, create a baseline to track only new vulnerabilities:

```bash
# Save current findings as baseline
vulnpredict scan . --format json --save-baseline baseline.json

# Future scans only report new findings
vulnpredict scan . --baseline baseline.json
```

Commit `baseline.json` to your repository and update it periodically after security reviews.

## Troubleshooting

**"No findings detected"** — VulnPredict only scans supported file types (.py, .js, .ts, .tsx, .go, .tf, Dockerfile, .yaml). Verify that your project contains files in these formats.

**"Model not found" warning** — The ML prediction model is optional. VulnPredict works without it using rule-based detection. To use ML features, train a model with `vulnpredict train`.

**Slow scans** — Use the `--profile quick` flag for faster scans that skip taint analysis and ML prediction. This is recommended for pre-commit hooks.

**False positives** — Use the `--min-severity high` flag to suppress low-confidence findings, or create a baseline file to track only new issues.

## Next Steps

Explore the [User Guide](../guide/scanning.md) for advanced features, learn to [write custom rules](../rule-authoring.md), or set up the [Dashboard API](../api/dashboard.md) for centralized results management.
