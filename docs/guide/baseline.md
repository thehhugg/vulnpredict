# Baseline Comparison

Baseline comparison allows teams to track only **new** vulnerabilities introduced since a previous scan. This is essential for incremental adoption in large codebases where fixing all existing issues at once is impractical.

## Creating a Baseline

Save the current scan results as a baseline file:

```bash
vulnpredict scan /path/to/project --format json --save-baseline baseline.json
```

This runs a normal scan and writes the results in JSON format to `baseline.json`.

## Scanning Against a Baseline

On subsequent scans, pass the baseline file to filter out previously known findings:

```bash
vulnpredict scan /path/to/project --baseline baseline.json
```

Only findings that are **not** present in the baseline are reported. This means the exit code reflects only new vulnerabilities, making it safe to enforce a zero-new-vulnerabilities policy in CI.

## Fuzzy Line Matching

VulnPredict uses fuzzy matching when comparing findings to the baseline. If a finding has the same file, rule, and severity but the line number has shifted by a small amount (due to code changes above the vulnerable line), it is still recognized as a known issue and suppressed.

## CI/CD Workflow

A typical CI workflow stores the baseline in the repository and updates it periodically:

```yaml
- name: Scan for new vulnerabilities
  run: vulnpredict scan . --baseline baseline.json --format sarif --output results.sarif

- name: Upload results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

To update the baseline after a release:

```bash
vulnpredict scan . --format json --save-baseline baseline.json
git add baseline.json
git commit -m "chore: update vulnerability baseline"
```
