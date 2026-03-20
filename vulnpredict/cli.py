import os
import time

import click
import pandas as pd

from .data_ingest import fetch_nvd_cve_data
from .formatters.json_fmt import format_json, write_json
from .interprocedural_taint import analyze_project as analyze_interprocedural_taint
from .js_analyzer import analyze_js_project
from .ml import predict, train_model
from .pattern_extract import extract_patterns_from_nvd
from .py_analyzer import analyze_python_project

MODEL_PATH = "vulnpredict_model.joblib"


@click.group()
def main():
    """VulnPredict CLI"""
    pass


@main.command()
@click.argument("year", type=int)
@click.argument("out_file")
def fetch_nvd(year, out_file):
    """Fetch NVD CVE data for a given YEAR and save to OUT_FILE (JSON)."""
    fetch_nvd_cve_data(year, out_file)


@main.command()
@click.argument("nvd_json")
@click.argument("out_csv")
def extract_nvd_patterns(nvd_json, out_csv):
    """Extract patterns from NVD JSON and save to OUT_CSV."""
    df = extract_patterns_from_nvd(nvd_json)
    df.to_csv(out_csv, index=False)
    click.echo(f"[VulnPredict] Extracted patterns saved to {out_csv}")


def _count_scannable_files(path):
    """Count Python and JavaScript files in the scan path."""
    count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            if f.endswith((".py", ".js", ".jsx", ".ts", ".tsx")):
                count += 1
    return count


@main.command()
@click.argument("path")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format for scan results.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--compact",
    is_flag=True,
    default=False,
    help="Produce minified JSON output (only with --format json).",
)
def scan(path, output_format, output_file, compact):
    """Scan the given codebase for potential vulnerabilities."""
    if not os.path.exists(path):
        click.echo(f"[VulnPredict] Path not found: {path}")
        return

    scan_start = time.time()

    # Auto-train if model is missing
    if not os.path.exists(MODEL_PATH):
        click.secho(
            "[VulnPredict] No trained model found. Auto-training on demo_project...",
            fg="yellow",
        )
        from .generate_labeled_data import main as gen_data_main
        from .ml import extract_features, train_model

        demo_dir = os.path.join(os.path.dirname(__file__), "..", "demo_project")
        demo_dir = os.path.abspath(demo_dir)
        labeled_csv = "labeled_findings.csv"
        gen_data_main.callback(demo_dir, labeled_csv)
        df = pd.read_csv(labeled_csv)
        raw_features = df.drop(columns=["label"])
        labels = df["label"].astype(int)
        features = extract_features(raw_features.to_dict(orient="records"))
        train_model(features, labels, model_path=MODEL_PATH)
        click.secho("[VulnPredict] Model trained. Proceeding with scan...", fg="green")

    click.echo(f"[VulnPredict] Scanning {path} for Python vulnerabilities...")
    py_findings = analyze_python_project(path)
    click.echo(f"[VulnPredict] Found {len(py_findings)} Python findings.")

    click.echo(f"[VulnPredict] Scanning {path} for JavaScript vulnerabilities...")
    js_findings = analyze_js_project(path)
    click.echo(f"[VulnPredict] Found {len(js_findings)} JavaScript findings.")

    click.echo("[VulnPredict] Running interprocedural taint analysis...")
    interproc_findings = analyze_interprocedural_taint(path)
    click.echo(
        f"[VulnPredict] Found {len(interproc_findings)} interprocedural taint findings."
    )

    all_findings = py_findings + js_findings + interproc_findings
    scan_duration = time.time() - scan_start
    file_count = _count_scannable_files(path)

    # Try to score findings with the ML model
    scored_findings = all_findings
    try:
        scored_findings = predict(all_findings)
    except Exception:
        pass

    # --- JSON output ---
    if output_format == "json":
        if output_file:
            write_json(
                scored_findings,
                scan_path=path,
                output_path=output_file,
                scan_duration=scan_duration,
                file_count=file_count,
                compact=compact,
            )
            click.echo(f"[VulnPredict] JSON results written to {output_file}")
        else:
            json_str = format_json(
                scored_findings,
                scan_path=path,
                scan_duration=scan_duration,
                file_count=file_count,
                compact=compact,
            )
            click.echo(json_str)
        return

    # --- Text output (default) ---
    if scored_findings:
        click.echo("\n=== Vulnerability Findings ===")
        high, med, low = 0, 0, 0
        for finding in scored_findings:
            score = finding.get("vuln_score", 0)
            if score >= 0.8:
                color = "red"
                high += 1
            elif score >= 0.5:
                color = "yellow"
                med += 1
            else:
                color = "green"
                low += 1
            click.echo(click.style(f"[score={score:.2f}] {finding}", fg=color))
        click.echo("\n=== Summary ===")
        click.echo(f"High risk:   {high}")
        click.echo(f"Medium risk: {med}")
        click.echo(f"Low risk:    {low}")
        click.echo(f"Total:       {len(scored_findings)} findings")
    else:
        click.echo("No potential vulnerabilities found.")

    if output_file:
        # Write text output to file
        with open(output_file, "w") as f:
            for finding in scored_findings:
                f.write(str(finding) + "\n")
        click.echo(f"[VulnPredict] Results written to {output_file}")


@main.command()
@click.argument("csv_file")
def train(csv_file):
    """Train the ML model from a labeled CSV file."""
    df = pd.read_csv(csv_file)
    raw_features = df.drop(columns=["label"])
    labels = df["label"].astype(int)
    from .ml import extract_features

    features = extract_features(raw_features.to_dict(orient="records"))
    train_model(features, labels)
