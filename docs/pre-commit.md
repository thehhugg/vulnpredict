# Pre-Commit Hook

VulnPredict can run as a [pre-commit](https://pre-commit.com/) hook, catching
security vulnerabilities before code is committed.

## Quick Start

Add the following to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v0.4.0  # Use the latest release tag
    hooks:
      - id: vulnpredict-scan
```

Then install the hook:

```bash
pre-commit install
```

## How It Works

The hook runs `vulnpredict scan` with the **quick** profile by default, which
performs pattern matching only (no ML scoring or interprocedural analysis).
This keeps the hook fast enough for interactive use.

Only findings at **medium** severity or above are reported by default, reducing
noise from low-confidence findings during development.

## Configuration

### Custom Profile

To use a different scan profile, override the hook entry:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v0.4.0
    hooks:
      - id: vulnpredict-scan
        args: ["--profile", "standard"]
```

### Custom Severity Threshold

To change the minimum severity:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v0.4.0
    hooks:
      - id: vulnpredict-scan
        args: ["--min-severity", "high"]
```

### Custom Rules

To include custom rule directories:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v0.4.0
    hooks:
      - id: vulnpredict-scan
        args: ["--rules-dir", "./my-rules"]
```

### File Types

By default, the hook runs on Python, JavaScript, TypeScript, JSX, and TSX
files. To limit to specific types:

```yaml
repos:
  - repo: https://github.com/thehhugg/vulnpredict
    rev: v0.4.0
    hooks:
      - id: vulnpredict-scan
        types: [python]
```

## Performance

The **quick** profile typically completes in under 2 seconds for most
projects, making it suitable for pre-commit use. If you find the hook too
slow, consider:

1. Using `--min-severity high` to reduce output processing
2. Limiting file types to only the languages you use
3. Adding a `.vulnpredict.yml` config with appropriate `exclude` patterns

## CI Integration

For CI pipelines, use the **standard** or **deep** profile instead:

```bash
vulnpredict scan . --profile standard --format sarif --output results.sarif
```

See the [scan profiles documentation](../docs/rule-authoring.md) for details
on what each profile includes.
