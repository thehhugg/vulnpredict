"""VulnPredict CLI — command-line interface for the vulnerability scanner."""

import os
import sys
import time

import click

from .logging_config import configure_logging, get_logger

logger = get_logger(__name__)

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

MODEL_PATH = "vulnpredict_model.joblib"


@click.group()
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable verbose output.")
@click.option("--debug", is_flag=True, default=False, help="Enable debug output (very verbose).")
@click.option(
    "--log-file",
    type=click.Path(),
    default=None,
    help="Write log output to a file in addition to stderr.",
)
@click.pass_context
def main(ctx, verbose, debug, log_file):
    """VulnPredict — Predictive Vulnerability Intelligence Tool."""
    ctx.ensure_object(dict)
    verbosity = 2 if debug else (1 if verbose else 0)
    configure_logging(verbosity=verbosity, log_file=log_file)
    ctx.obj["verbosity"] = verbosity


@main.command()
@click.argument("year", type=int)
@click.argument("out_file")
def fetch_nvd(year, out_file):
    """Fetch NVD CVE data for a given YEAR and save to OUT_FILE (JSON)."""
    try:
        from .data_ingest import fetch_nvd_cve_data

        fetch_nvd_cve_data(year, out_file)
    except ImportError as exc:
        logger.error("Missing dependency for NVD fetching: %s", exc)
        sys.exit(EXIT_ERROR)
    except Exception as exc:
        logger.error("Failed to fetch NVD data for year %d: %s", year, exc)
        logger.debug("Traceback:", exc_info=True)
        sys.exit(EXIT_ERROR)


@main.command()
@click.argument("nvd_json")
@click.argument("out_csv")
def extract_nvd_patterns(nvd_json, out_csv):
    """Extract patterns from NVD JSON and save to OUT_CSV."""
    try:
        import pandas as pd

        from .pattern_extract import extract_patterns_from_nvd

        if not os.path.isfile(nvd_json):
            logger.error("NVD JSON file not found: %s", nvd_json)
            sys.exit(EXIT_ERROR)
        df = extract_patterns_from_nvd(nvd_json)
        df.to_csv(out_csv, index=False)
        click.echo(f"[VulnPredict] Extracted patterns saved to {out_csv}")
    except Exception as exc:
        logger.error("Failed to extract NVD patterns: %s", exc)
        logger.debug("Traceback:", exc_info=True)
        sys.exit(EXIT_ERROR)


def _count_scannable_files(path):
    """Count Python and JavaScript files in the scan path."""
    count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            if f.endswith((".py", ".js", ".jsx", ".ts", ".tsx")):
                count += 1
    return count


def _auto_train_model():
    """Auto-train the ML model on the demo project if no model exists."""
    logger.info("No trained model found. Auto-training on demo_project...")
    try:
        import pandas as pd

        from .generate_labeled_data import main as gen_data_main
        from .ml import extract_features, train_model

        demo_dir = os.path.join(os.path.dirname(__file__), "..", "demo_project")
        demo_dir = os.path.abspath(demo_dir)
        if not os.path.isdir(demo_dir):
            logger.warning(
                "Demo project not found at %s. Skipping auto-training.", demo_dir
            )
            return False
        labeled_csv = "labeled_findings.csv"
        gen_data_main.callback(demo_dir, labeled_csv)
        df = pd.read_csv(labeled_csv)
        raw_features = df.drop(columns=["label"])
        labels = df["label"].astype(int)
        features = extract_features(raw_features.to_dict(orient="records"))
        train_model(features, labels, model_path=MODEL_PATH)
        logger.info("Model trained successfully.")
        return True
    except ImportError as exc:
        logger.warning(
            "ML dependencies not available (%s). Scanning without ML scoring.", exc
        )
        return False
    except Exception as exc:
        logger.warning("Auto-training failed: %s. Scanning without ML scoring.", exc)
        logger.debug("Traceback:", exc_info=True)
        return False


def _run_python_scan(path):
    """Run Python vulnerability analysis with error handling."""
    try:
        from .py_analyzer import analyze_python_project

        logger.info("Scanning %s for Python vulnerabilities...", path)
        findings = analyze_python_project(path)
        logger.info("Found %d Python findings.", len(findings))
        return findings
    except ImportError as exc:
        logger.warning("Python analyzer unavailable (%s). Skipping.", exc)
        return []
    except Exception as exc:
        logger.error("Python analysis failed: %s", exc)
        logger.debug("Traceback:", exc_info=True)
        return []


def _run_js_scan(path):
    """Run JavaScript vulnerability analysis with error handling."""
    try:
        from .js_analyzer import analyze_js_project

        logger.info("Scanning %s for JavaScript vulnerabilities...", path)
        findings = analyze_js_project(path)
        logger.info("Found %d JavaScript findings.", len(findings))
        return findings
    except ImportError as exc:
        logger.warning("JavaScript analyzer unavailable (%s). Skipping.", exc)
        return []
    except Exception as exc:
        logger.error("JavaScript analysis failed: %s", exc)
        logger.debug("Traceback:", exc_info=True)
        return []


def _run_taint_analysis(path):
    """Run interprocedural taint analysis with error handling."""
    try:
        from .interprocedural_taint import analyze_project as analyze_interprocedural_taint

        logger.info("Running interprocedural taint analysis...")
        findings = analyze_interprocedural_taint(path)
        logger.info("Found %d interprocedural taint findings.", len(findings))
        return findings
    except ImportError as exc:
        logger.warning("Taint analysis unavailable (%s). Skipping.", exc)
        return []
    except Exception as exc:
        logger.error("Taint analysis failed: %s", exc)
        logger.debug("Traceback:", exc_info=True)
        return []


def _score_findings(findings):
    """Score findings with the ML model, falling back gracefully."""
    try:
        from .ml import predict

        scored = predict(findings)
        logger.info("ML scoring applied to %d findings.", len(scored))
        return scored
    except ImportError:
        logger.debug("ML dependencies not available. Returning unscored findings.")
        return findings
    except Exception as exc:
        logger.warning("ML scoring failed: %s. Returning unscored findings.", exc)
        logger.debug("Traceback:", exc_info=True)
        return findings


@main.command()
@click.argument("path")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif", "html"], case_sensitive=False),
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
@click.option(
    "--baseline",
    type=click.Path(exists=True),
    default=None,
    help="Path to a previous scan result (JSON) for differential scanning.",
)
@click.option(
    "--show-suppressed",
    is_flag=True,
    default=False,
    help="Include suppressed findings in the output.",
)
@click.pass_context
def scan(ctx, path, output_format, output_file, compact, baseline, show_suppressed):
    """Scan the given codebase for potential vulnerabilities."""
    if not os.path.exists(path):
        logger.error("Scan path not found: %s", path)
        sys.exit(EXIT_ERROR)

    scan_start = time.time()
    abs_path = os.path.abspath(path)
    logger.info("Starting scan of %s (format=%s)", abs_path, output_format)

    # Load suppression configuration
    from .suppression import IgnoreFile, apply_suppressions, load_baseline

    ignore_file = IgnoreFile.from_project(abs_path)
    baseline_findings = load_baseline(baseline) if baseline else None

    # Auto-train if model is missing
    model_available = os.path.exists(MODEL_PATH)
    if not model_available:
        model_available = _auto_train_model()

    # Run all analyzers
    py_findings = _run_python_scan(path)
    js_findings = _run_js_scan(path)
    interproc_findings = _run_taint_analysis(path)

    all_findings = py_findings + js_findings + interproc_findings
    scan_duration = time.time() - scan_start
    file_count = _count_scannable_files(path)

    logger.info(
        "Scan complete: %d findings in %.2fs (%d files scanned)",
        len(all_findings),
        scan_duration,
        file_count,
    )

    # Apply suppressions
    active_findings, suppressed_findings = apply_suppressions(
        all_findings,
        project_root=abs_path,
        ignore_file=ignore_file,
        baseline=baseline_findings,
    )

    # Score findings with ML model (skip if no model available)
    if model_available:
        scored_findings = _score_findings(active_findings)
    else:
        logger.info("No ML model available. Returning unscored findings.")
        scored_findings = active_findings

    # Determine which findings to output
    output_findings = scored_findings
    if show_suppressed:
        output_findings = scored_findings + suppressed_findings

    # --- HTML output ---
    if output_format == "html":
        try:
            from .formatters.html import format_html, write_html

            if not output_file:
                output_file = "vulnpredict-report.html"
            write_html(
                output_findings,
                scan_path=path,
                output_path=output_file,
                scan_duration=scan_duration,
                file_count=file_count,
            )
            click.echo(f"[VulnPredict] HTML report written to {output_file}")
        except Exception as exc:
            logger.error("Failed to generate HTML report: %s", exc)
            logger.debug("Traceback:", exc_info=True)
            sys.exit(EXIT_ERROR)
        _print_suppression_summary(suppressed_findings)
        return

    # --- SARIF output ---
    if output_format == "sarif":
        try:
            from .formatters.sarif import format_sarif, write_sarif

            if output_file:
                write_sarif(output_findings, scan_path=path, output_path=output_file)
                click.echo(f"[VulnPredict] SARIF results written to {output_file}")
            else:
                sarif_str = format_sarif(output_findings, scan_path=path)
                click.echo(sarif_str)
        except Exception as exc:
            logger.error("Failed to generate SARIF output: %s", exc)
            logger.debug("Traceback:", exc_info=True)
            sys.exit(EXIT_ERROR)
        _print_suppression_summary(suppressed_findings)
        return

    # --- JSON output ---
    if output_format == "json":
        try:
            from .formatters.json_fmt import format_json, write_json

            if output_file:
                write_json(
                    output_findings,
                    scan_path=path,
                    output_path=output_file,
                    scan_duration=scan_duration,
                    file_count=file_count,
                    compact=compact,
                    suppressed_count=len(suppressed_findings),
                )
                click.echo(f"[VulnPredict] JSON results written to {output_file}")
            else:
                json_str = format_json(
                    output_findings,
                    scan_path=path,
                    scan_duration=scan_duration,
                    file_count=file_count,
                    compact=compact,
                    suppressed_count=len(suppressed_findings),
                )
                click.echo(json_str)
        except Exception as exc:
            logger.error("Failed to generate JSON output: %s", exc)
            logger.debug("Traceback:", exc_info=True)
            sys.exit(EXIT_ERROR)
        _print_suppression_summary(suppressed_findings)
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

    _print_suppression_summary(suppressed_findings)

    if show_suppressed and suppressed_findings:
        click.echo("\n=== Suppressed Findings ===")
        for finding in suppressed_findings:
            reason = finding.get("suppression_reason", "unknown")
            click.echo(click.style(f"[suppressed:{reason}] {finding}", fg="cyan"))

    if output_file:
        try:
            with open(output_file, "w") as f:
                for finding in output_findings:
                    f.write(str(finding) + "\n")
            click.echo(f"[VulnPredict] Results written to {output_file}")
        except OSError as exc:
            logger.error("Failed to write output file %s: %s", output_file, exc)
            sys.exit(EXIT_ERROR)


def _print_suppression_summary(suppressed_findings):
    """Print a summary of suppressed findings by reason."""
    if not suppressed_findings:
        return
    reasons = {}
    for f in suppressed_findings:
        reason = f.get("suppression_reason", "unknown")
        reasons[reason] = reasons.get(reason, 0) + 1
    click.echo(f"\n[VulnPredict] {len(suppressed_findings)} finding(s) suppressed:")
    for reason, count in sorted(reasons.items()):
        click.echo(f"  - {reason}: {count}")


@main.command()
@click.argument("csv_file")
def train(csv_file):
    """Train the ML model from a labeled CSV file."""
    try:
        import pandas as pd

        from .ml import extract_features, train_model

        if not os.path.isfile(csv_file):
            logger.error("CSV file not found: %s", csv_file)
            sys.exit(EXIT_ERROR)
        df = pd.read_csv(csv_file)
        raw_features = df.drop(columns=["label"])
        labels = df["label"].astype(int)
        features = extract_features(raw_features.to_dict(orient="records"))
        train_model(features, labels)
    except ImportError as exc:
        logger.error("ML dependencies not available: %s", exc)
        sys.exit(EXIT_ERROR)
    except Exception as exc:
        logger.error("Training failed: %s", exc)
        logger.debug("Traceback:", exc_info=True)
        sys.exit(EXIT_ERROR)
