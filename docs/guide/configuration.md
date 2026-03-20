# Configuration

VulnPredict can be configured through command-line flags, environment variables, and a YAML configuration file.

## Configuration File

Create a `.vulnpredict.yml` file in your project root:

```yaml
format: json
min_severity: medium
profile: standard
rules_dir: ./custom-rules
output: results.json
```

Command-line flags take precedence over the configuration file.

## Environment Variables

The following environment variables are recognized:

| Variable | Description | Default |
|---|---|---|
| `VULNPREDICT_API_KEY` | API key for the dashboard API | (none) |
| `VULNPREDICT_DB_PATH` | SQLite database path for the dashboard | `vulnpredict_dashboard.db` |
| `VULNPREDICT_MODEL_PATH` | Path to the trained ML model | (auto-detected) |

## CLI Reference

The full set of CLI options for the `scan` command:

```
vulnpredict scan [OPTIONS] PATH

Options:
  --format TEXT          Output format: json, sarif, html, markdown
  --output TEXT          Write output to file instead of stdout
  --profile TEXT         Scan profile: quick, standard, deep
  --min-severity TEXT    Minimum severity to report: low, medium, high, critical
  --baseline TEXT        Path to baseline JSON for comparison
  --save-baseline TEXT   Save current results as baseline
  --rules-dir TEXT       Path to directory with custom YAML rules
  --no-secrets           Disable secrets detection
  --help                 Show help message
```
