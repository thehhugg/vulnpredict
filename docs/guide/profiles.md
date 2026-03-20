# Scan Profiles

Scan profiles control the depth and speed of analysis. VulnPredict ships with three built-in profiles.

## Quick Profile

The **quick** profile runs only pattern-matching rules without taint analysis or ML prediction. It is designed for pre-commit hooks and rapid feedback loops where speed is critical.

```bash
vulnpredict scan /path/to/project --profile quick
```

Typical scan time is under 2 seconds for most projects.

## Standard Profile

The **standard** profile is the default. It runs pattern matching, taint analysis, and interprocedural analysis but skips the ML prediction model. This profile provides a good balance between speed and accuracy for CI/CD pipelines.

```bash
vulnpredict scan /path/to/project --profile standard
```

## Deep Profile

The **deep** profile enables all analysis passes including the ML-based vulnerability prediction model. It provides the most comprehensive results and is recommended for release audits and security reviews.

```bash
vulnpredict scan /path/to/project --profile deep
```

The deep profile requires a trained model. If no model is available, it falls back to the standard profile with a warning.

## Comparison

| Feature | Quick | Standard | Deep |
|---|---|---|---|
| Pattern matching | Yes | Yes | Yes |
| Taint analysis | No | Yes | Yes |
| Interprocedural analysis | No | Yes | Yes |
| ML prediction | No | No | Yes |
| Secrets detection | Yes | Yes | Yes |
| IaC scanning | Yes | Yes | Yes |
