# Python API Reference

VulnPredict can be used as a Python library in addition to the CLI. This page documents the key public APIs.

## Python Analyzer

```python
from vulnpredict.py_analyzer import analyze_python_file, scan_directory

# Scan a single file
findings = analyze_python_file("/path/to/file.py")

# Scan a directory
findings = scan_directory("/path/to/project")
```

Each finding is a dictionary containing the file path, line number, severity, vulnerability type, CWE identifier, and a human-readable message.

## JavaScript Analyzer

```python
from vulnpredict.js_analyzer import analyze_js_file
from vulnpredict.js_security_patterns import scan_js_directory

findings = analyze_js_file("/path/to/file.js")
findings = scan_js_directory("/path/to/project")
```

## Go Analyzer

```python
from vulnpredict.go_analyzer import scan_go_file, scan_go_directory

findings = scan_go_file("/path/to/file.go")
findings = scan_go_directory("/path/to/project")
```

## IaC Analyzer

```python
from vulnpredict.iac_analyzer import scan_iac_file, scan_iac_directory

findings = scan_iac_file("/path/to/main.tf")
findings = scan_iac_directory("/path/to/infra")
```

## Secrets Detector

```python
from vulnpredict.secrets_detector import scan_file_for_secrets

findings = scan_file_for_secrets("/path/to/config.py")
```

## Rule Engine

```python
from vulnpredict.rules import RuleEngine

engine = RuleEngine()
engine.load_builtin_rules()
engine.load_rules_from_directory("/path/to/custom-rules")

# Get all loaded rules
rules = engine.get_rules()
```

## ML Pipeline

```python
from vulnpredict.ml import predict_vulnerability

# Requires a trained model
result = predict_vulnerability(features_dict, model_path="/path/to/model.pt")
```
