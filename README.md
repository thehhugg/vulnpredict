# VulnPredict

**Predictive Vulnerability Intelligence Tool**

VulnPredict is an open source project that applies static analysis and machine learning to uncover potential software vulnerabilities before they are publicly disclosed. It inspects both Python and JavaScript code, learns from historical vulnerability patterns, and highlights risky areas of a codebase.

## Features
- **Taint Analysis** tracks untrusted data flows from sources to dangerous sinks.
- **Code Churn & Author Metrics** leverage git history to spot frequently changed files.
- **Dependency Risk Analysis** flags outdated or vulnerable third‑party packages.
- **Sensitive Data Detection** looks for passwords, tokens and other secrets.
- **Deep Code Embeddings** via CodeBERT for semantic understanding of code.
- **Interprocedural Taint Analysis** follows data across function boundaries.
- **NVD/CVE Pattern Mining** extracts real‑world vulnerability patterns.
- Multi‑language support (Python and JavaScript) with CLI friendly output.

## Repository Layout
- `vulnpredict/` &ndash; source code for analyzers and the ML pipeline.
- `demo_project/` &ndash; sample vulnerable project used for demos and training.
- `requirements.txt` &ndash; Python dependencies.
- `setup.py` &ndash; package metadata and console entry point.

## Installation
1. Clone this repository.
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
   JavaScript analysis additionally requires Node.js and npm for `esprima` and optional ESLint.

## Quickstart with the Demo Project
Generate labeled data, train the model and scan the included demo project:
```sh
python -m vulnpredict.generate_labeled_data demo_project labeled_findings.csv
python -m vulnpredict train labeled_findings.csv
python -m vulnpredict scan demo_project
```

## CLI Usage
The package installs a `vulnpredict` command with subcommands:

- `vulnpredict fetch-nvd YEAR OUT_JSON` &ndash; download CVE data from the NVD.
- `vulnpredict extract-nvd-patterns NVD_JSON OUT_CSV` &ndash; mine patterns from the NVD data.
- `vulnpredict train CSV_FILE` &ndash; train the ML model from labeled findings.
- `vulnpredict scan PATH` &ndash; analyze a codebase and print prioritized results.

## ML Pipeline Overview
1. **Feature Extraction** combines static analysis, taint tracking, dependency risk, sensitive data detection, and code embeddings.
2. **Model Training** uses scikit-learn (Random Forest by default) on labeled findings.
3. **Prediction** scores new findings with a vulnerability likelihood.

## Contributing
Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidance on adding analyzers, rules or ML improvements.

## License
This project is released under the [MIT](LICENSE) license.
