# VulnPredict Demo Project

This directory contains intentionally vulnerable code for testing VulnPredict.

## Included Vulnerabilities

### Python (`vuln_python.py`)
- **Eval Injection:** Use of `eval` with user input
- **SQL Injection:** Unsanitized SQL query with string formatting
- **Hardcoded Password:** Sensitive data in code
- **Outdated Dependency:** Import of a module with known past vulnerabilities

### JavaScript (`vuln_js.js`)
- **Eval Injection:** Use of `eval` with user input
- **XSS:** Unsanitized assignment to `innerHTML`
- **Hardcoded API Key:** Sensitive data in code
- **Outdated Dependency:** Require of a module with known past vulnerabilities

## How to Scan

From the VulnPredict project root, run:

```sh
python -m vulnpredict scan demo_project
```

You should see findings for code injection, SQL injection, XSS, sensitive data, and outdated dependencies. 