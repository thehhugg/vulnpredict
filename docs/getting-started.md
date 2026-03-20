# Getting Started with VulnPredict

## Prerequisites

- Python 3.9 or higher
- Node.js and npm (for JavaScript analysis)
- Git

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/thehhugg/vulnpredict.git
   cd vulnpredict
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Install Node.js dependencies for JavaScript analysis:
   ```bash
   npm install -g esprima
   ```

## Quick Start Example

1. Generate labeled data from a demo project:
   ```bash
   python -m vulnpredict.generate_labeled_data demo_project labeled_findings.csv
   ```

2. Train the machine learning model:
   ```bash
   python -m vulnpredict train labeled_findings.csv
   ```

3. Scan a codebase for vulnerabilities:
   ```bash
   python -m vulnpredict scan demo_project
   ```

## Expected Output

The scan command produces a prioritized list of potential vulnerabilities:

```
Scanning demo_project...

Vulnerability Likelihood: HIGH
- File: demo_project/app.py
  Line: 42
  Issue: SQL Injection vulnerability detected
  Description: User input flows to SQL query without proper sanitization
  Risk Score: 0.92

Vulnerability Likelihood: MEDIUM
- File: demo_project/config.py
  Line: 15
  Issue: Hardcoded password found
  Description: Password stored in plaintext
  Risk Score: 0.65

Total findings: 2
Scan completed in 3.2 seconds.
```

## CLI Commands

VulnPredict provides several CLI commands:

- `vulnpredict fetch-nvd YEAR OUT_JSON` - Download CVE data from NVD
- `vulnpredict extract-nvd-patterns NVD_JSON OUT_CSV` - Mine patterns from NVD data
- `vulnpredict train CSV_FILE` - Train the ML model from labeled findings
- `vulnpredict scan PATH` - Analyze a codebase and print prioritized results

## Next Steps

- Explore the demo project in `demo_project/` to understand the analysis
- Check the `tests/` directory for example usage
- Contribute to the project by adding new analyzers or improving existing ones