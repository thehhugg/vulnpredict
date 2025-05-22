# VulnPredict

**Predictive Vulnerability Intelligence Tool**

VulnPredict is an open source tool that uses advanced machine learning and code intelligence to predict potential vulnerabilities in software before they're discovered and disclosed. Unlike traditional security tools that only identify known vulnerabilities, VulnPredict proactively analyzes code patterns, development practices, and historical vulnerability data to highlight code areas likely to contain undiscovered vulnerabilities.

## Core Features
- **Taint Analysis:** Tracks untrusted data from sources to dangerous sinks to detect real vulnerability flows (e.g., injection flaws).
- **Code Churn & Author Features:** Uses git history to identify files with high change frequency or many authors, which are more likely to contain bugs.
- **Dependency Risk Analysis:** Flags outdated or known-vulnerable dependencies using PyPI and (optionally) vulnerability databases.
- **Sensitive Data Detection:** Identifies code that handles sensitive data (passwords, tokens, PII) for higher risk prioritization.
- **Code Embeddings (Deep Learning):** Uses CodeBERT to capture the semantic meaning of code, enabling detection of subtle and novel vulnerabilities.
- **Interprocedural Taint Analysis:** Tracks data flows across function and file boundaries for deep vulnerability detection.
- **NVD/CVE Pattern Mining:** Leverage real-world vulnerability data to extract patterns and enhance ML and rule-based detection.
- Multi-language code analysis (Python, JavaScript)
- Actionable, prioritized reporting
- CLI and API-first design for easy integration

## About the Pre-trained Model

*A pre-trained model will be available soon!*

In the meantime, you can train your own model using the demo project and included pipeline:

```sh
python -m vulnpredict.generate_labeled_data demo_project labeled_findings.csv
python -m vulnpredict train labeled_findings.csv
python -m vulnpredict scan demo_project
```

## Quickstart (with Demo Project)

1. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
2. **Generate labeled data from the demo project:**
   ```sh
   python -m vulnpredict.generate_labeled_data demo_project labeled_findings.csv
   ```
3. **Train the model:**
   ```sh
   python -m vulnpredict train labeled_findings.csv
   ```
4. **Scan the demo project:**
   ```sh
   python -m vulnpredict scan demo_project
   ```
5. **See instant ML-powered results!**

## Usage

### Fetch NVD CVE Data
Fetch CVE data from the NVD for a given year:
```sh
python -m vulnpredict fetch-nvd 2023 nvd_cve_2023.json
```

### Extract Patterns from NVD Data
Extract vulnerability patterns (CWE, products, descriptions) from NVD JSON:
```sh
python -m vulnpredict extract-nvd-patterns nvd_cve_2023.json nvd_patterns_2023.csv
```

### Generate Labeled Data for ML Training
Analyze a codebase and generate a labeled CSV with all features:
```sh
python -m vulnpredict.generate_labeled_data /path/to/code /path/to/labeled_findings.csv
```

### Train the ML Model
Train the model using the generated CSV:
```sh
python -m vulnpredict train /path/to/labeled_findings.csv
```

### Scan a Codebase with ML Predictions
Scan a new codebase and get ML-powered vulnerability predictions:
```sh
python -m vulnpredict scan /path/to/new/code
```

## ML Pipeline Overview
- **Feature Extraction:** Combines static analysis, taint analysis, code churn, dependency risk, sensitive data detection, deep code embeddings, and real-world CVE pattern mining.
- **Model Training:** Uses a Random Forest classifier (or can be extended) to learn from labeled findings.
- **Prediction:** Scores new findings with a vulnerability likelihood, leveraging all features.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing analyzers, rules, and models.

## License
[MIT](LICENSE) 