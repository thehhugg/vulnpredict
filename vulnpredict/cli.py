import click
import os
from .py_analyzer import analyze_python_project
from .js_analyzer import analyze_js_project
from .ml import train_model, predict, load_model
from .interprocedural_taint import analyze_project as analyze_interprocedural_taint
from .data_ingest import fetch_nvd_cve_data
from .pattern_extract import extract_patterns_from_nvd
import pandas as pd

MODEL_PATH = 'vulnpredict_model.joblib'

@click.group()
def main():
    """VulnPredict CLI"""
    pass

@main.command()
@click.argument('year', type=int)
@click.argument('out_file')
def fetch_nvd(year, out_file):
    """Fetch NVD CVE data for a given YEAR and save to OUT_FILE (JSON)."""
    fetch_nvd_cve_data(year, out_file)

@main.command()
@click.argument('nvd_json')
@click.argument('out_csv')
def extract_nvd_patterns(nvd_json, out_csv):
    """Extract patterns from NVD JSON and save to OUT_CSV."""
    df = extract_patterns_from_nvd(nvd_json)
    df.to_csv(out_csv, index=False)
    click.echo(f"[VulnPredict] Extracted patterns saved to {out_csv}")

@main.command()
@click.argument('path')
def scan(path):
    """Scan the given codebase for potential vulnerabilities."""
    if not os.path.exists(path):
        click.echo(f"[VulnPredict] Path not found: {path}")
        return
    # Auto-train if model is missing
    if not os.path.exists(MODEL_PATH):
        click.secho("[VulnPredict] No trained model found. Auto-training on demo_project...", fg='yellow')
        from .generate_labeled_data import main as gen_data_main
        from .ml import train_model
        demo_dir = os.path.join(os.path.dirname(__file__), '..', 'demo_project')
        demo_dir = os.path.abspath(demo_dir)
        labeled_csv = 'labeled_findings.csv'
        # Generate labeled data
        gen_data_main.callback(demo_dir, labeled_csv)
        # Train model
        df = pd.read_csv(labeled_csv)
        features = df.drop(columns=['label'])
        labels = df['label'].astype(int)
        train_model(features, labels, model_path=MODEL_PATH)
        click.secho("[VulnPredict] Model trained. Proceeding with scan...", fg='green')
    click.echo(f"[VulnPredict] Scanning {path} for Python vulnerabilities...")
    py_findings = analyze_python_project(path)
    click.echo(f"[VulnPredict] Found {len(py_findings)} Python findings.")
    click.echo(f"[VulnPredict] Scanning {path} for JavaScript vulnerabilities...")
    js_findings = analyze_js_project(path)
    click.echo(f"[VulnPredict] Found {len(js_findings)} JavaScript findings.")
    click.echo(f"[VulnPredict] Running interprocedural taint analysis...")
    interproc_findings = analyze_interprocedural_taint(path)
    click.echo(f"[VulnPredict] Found {len(interproc_findings)} interprocedural taint findings.")
    all_findings = py_findings + js_findings + interproc_findings
    if all_findings:
        try:
            # Try to score findings with the ML model
            scored = predict(all_findings)
            click.echo("\n=== Vulnerability Findings (with ML scores) ===")
            # Colorize and summarize
            high, med, low = 0, 0, 0
            for finding in scored:
                score = finding.get('vuln_score', 0)
                if score >= 0.8:
                    color = 'red'
                    high += 1
                elif score >= 0.5:
                    color = 'yellow'
                    med += 1
                else:
                    color = 'green'
                    low += 1
                click.echo(click.style(f"[score={score:.2f}] {finding}", fg=color))
            click.echo("\n=== Summary ===")
            click.echo(f"High risk:   {high}")
            click.echo(f"Medium risk: {med}")
            click.echo(f"Low risk:    {low}")
            click.echo(f"Total:       {len(scored)} findings")
        except Exception as e:
            click.echo(f"[VulnPredict] ML model not found or error: {e}")
            click.echo("\n=== Vulnerability Findings (raw) ===")
            for finding in all_findings:
                click.echo(str(finding))
    else:
        click.echo("No potential vulnerabilities found.")

@main.command()
@click.argument('csv_file')
def train(csv_file):
    """Train the ML model from a labeled CSV file."""
    df = pd.read_csv(csv_file)
    features = df.drop(columns=['label'])
    labels = df['label'].astype(int)
    train_model(features, labels) 