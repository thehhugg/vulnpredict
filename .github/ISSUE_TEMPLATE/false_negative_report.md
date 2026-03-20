---
name: False Negative Report
about: Report a known vulnerability that VulnPredict failed to detect
title: "[FN] "
labels: "false negative"
assignees: ""
---

## Summary

Briefly describe the vulnerability that VulnPredict missed.

## Vulnerability Type

- **Category**: (e.g., SQL Injection, XSS, Command Injection, Path Traversal, SSRF, Deserialization)
- **CWE ID** (if known): (e.g., CWE-89)
- **Severity**: (e.g., Critical, High, Medium, Low)

## Code Sample

Provide the minimal vulnerable code that VulnPredict should have flagged:

```python
# or javascript, etc.
# Paste the vulnerable code here
```

## Expected Finding

Describe what VulnPredict should have reported (finding type, severity, line number, etc.).

## VulnPredict Output

```
Paste the actual VulnPredict output (or confirm that no finding was produced)
```

## Environment

- **VulnPredict version**: (e.g., 0.1.0)
- **Language analyzed**: (e.g., Python 3.11, JavaScript ES2022)
- **Scan command used**: (e.g., `vulnpredict scan ./project/`)

## Reference

Link to any CVE, advisory, or documentation that confirms this is a real vulnerability.

## Additional Context

Add any other context (similar tools that do detect this, suggested detection approach, etc.).
