# Architecture

This page describes the high-level architecture of VulnPredict and how the components interact.

## Overview

VulnPredict follows a pipeline architecture where source files pass through multiple analysis stages. The CLI orchestrates the pipeline, and the results are formatted and output according to user preferences.

```
Source Files → Language Detection → Analyzers → Findings → Severity Scoring → Formatters → Output
                                       ↑
                                  Rule Engine
                                  ML Pipeline
```

## Analysis Pipeline

The scan command executes the following stages in order:

**Stage 1: File Discovery.** The CLI walks the target directory, identifies source files by extension, and groups them by language. Directories like `.git`, `node_modules`, and `vendor` are excluded.

**Stage 2: Language-Specific Analysis.** Each file is dispatched to the appropriate analyzer. The Python analyzer uses the `ast` module for AST-based analysis and performs interprocedural taint tracking. The JavaScript, TypeScript, and Go analyzers use regex-based pattern matching. The IaC analyzer checks Terraform, Dockerfile, and Kubernetes manifests for misconfigurations.

**Stage 3: Secrets Detection.** All files are scanned for hardcoded credentials and API keys using a library of regex patterns with entropy checks.

**Stage 4: Rule Engine.** Custom YAML rules are evaluated against the source code. The rule engine supports pattern matching with severity levels and CWE identifiers.

**Stage 5: ML Prediction (Deep profile only).** Feature vectors are extracted from the code and passed through a trained neural network to predict vulnerability likelihood.

**Stage 6: Severity Scoring.** Findings are assigned severity levels (critical, high, medium, low) based on the rule definitions and ML confidence scores.

**Stage 7: Suppression.** If a baseline file is provided, known findings are filtered out using fuzzy matching on file path, rule ID, and line number.

**Stage 8: Formatting.** The remaining findings are formatted according to the requested output format (JSON, SARIF, HTML, Markdown, or console).

## Key Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Click-based CLI, orchestrates the scan pipeline |
| `py_analyzer.py` | Python AST analysis and taint tracking |
| `interprocedural_taint.py` | Cross-function taint propagation |
| `js_analyzer.py` | JavaScript/TypeScript analysis |
| `go_analyzer.py` | Go security analysis |
| `iac_analyzer.py` | Infrastructure-as-Code analysis |
| `secrets_detector.py` | Credential and secret detection |
| `rules.py` | YAML-based custom rule engine |
| `ml.py` | ML model loading and prediction |
| `severity.py` | Severity scoring and ranking |
| `suppression.py` | Baseline comparison and finding suppression |
| `formatters/` | Output format implementations |
| `dashboard/` | FastAPI REST API for scan storage |
