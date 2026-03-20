# Baseline Scanning Guide

Baseline scanning enables **differential analysis** so that only **new** findings are reported. This prevents alert fatigue from pre-existing issues and lets teams adopt VulnPredict incrementally.

## Quick Start

### 1. Create a Baseline

Run a full scan and save the results as a baseline file:

```bash
vulnpredict scan ./my-project --save-baseline baseline.json
```

This produces a `baseline.json` file containing all current findings in JSON format.

### 2. Scan Against the Baseline

On subsequent scans (e.g. in CI), pass the baseline file to suppress known findings:

```bash
vulnpredict scan ./my-project --baseline baseline.json
```

Only **new** findings (not present in the baseline) will be reported. Known findings are suppressed with the reason `baseline`.

### 3. Update the Baseline

After addressing findings or accepting them as known, regenerate the baseline:

```bash
vulnpredict scan ./my-project --save-baseline baseline.json
```

## How Matching Works

VulnPredict uses a two-tier matching strategy to identify known findings:

| Strategy | Fields Compared | Purpose |
|---|---|---|
| **Exact match** | file + line + rule_id + message | Catches identical findings |
| **Fuzzy match** | file + rule_id + message (line within +/-5) | Catches findings that shifted due to small code edits |

The fuzzy matching tolerance of 5 lines means that if a finding moves by up to 5 lines (e.g. because a few lines were added above it), it is still recognized as a known finding and suppressed.

## CI Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install VulnPredict
        run: pip install vulnpredict

      - name: Run differential scan
        run: |
          # Download baseline from a known location (e.g. default branch artifact)
          # If no baseline exists yet, the scan runs without differential filtering
          if [ -f baseline.json ]; then
            vulnpredict scan . --baseline baseline.json --format sarif --output results.sarif
          else
            vulnpredict scan . --format sarif --output results.sarif
          fi

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Update baseline on main branch
        if: github.ref == 'refs/heads/main'
        run: |
          vulnpredict scan . --save-baseline baseline.json
          # Commit or upload baseline.json as an artifact
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - pip install vulnpredict
    - |
      if [ -f baseline.json ]; then
        vulnpredict scan . --baseline baseline.json --format json --output results.json
      else
        vulnpredict scan . --format json --output results.json
      fi
  artifacts:
    paths:
      - results.json
    reports:
      sast: results.json

update-baseline:
  stage: deploy
  only:
    - main
  script:
    - pip install vulnpredict
    - vulnpredict scan . --save-baseline baseline.json
  artifacts:
    paths:
      - baseline.json
```

## Combining with Other Options

Baseline scanning works alongside all other scan options:

```bash
# Differential scan with minimum severity filter
vulnpredict scan . --baseline baseline.json --min-severity high

# Differential scan with specific profile
vulnpredict scan . --baseline baseline.json --profile deep

# Save baseline and produce SARIF output simultaneously
vulnpredict scan . --save-baseline baseline.json --format sarif --output results.sarif

# Show suppressed baseline findings for debugging
vulnpredict scan . --baseline baseline.json --show-suppressed
```

## Best Practices

1. **Store the baseline in version control** or as a CI artifact so it is available for every pipeline run.
2. **Regenerate the baseline on the default branch** after merging PRs, so the baseline stays current.
3. **Review suppressed findings periodically** using `--show-suppressed` to ensure nothing important is being hidden.
4. **Use `--min-severity high`** in CI to fail only on high/critical new findings while still tracking medium/low ones in the baseline.
