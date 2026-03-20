"""VulnPredict CLI — command-line interface for the vulnerability scanner."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional

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
def main(ctx: click.Context, verbose: bool, debug: bool, log_file: Optional[str]) -> None:
    """VulnPredict — Predictive Vulnerability Intelligence Tool."""
    ctx.ensure_object(dict)
    verbosity = 2 if debug else (1 if verbose else 0)
    configure_logging(verbosity=verbosity, log_file=log_file)
    ctx.obj["verbosity"] = verbosity


@main.command()
@click.argument("year", type=int)
@click.argument("out_file")
def fetch_nvd(year: int, out_file: str) -> None:
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
def extract_nvd_patterns(nvd_json: str, out_csv: str) -> None:
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


def _count_scannable_files(path: str) -> int:
    """Count Python and JavaScript files in the scan path."""
    count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            if f.endswith((".py", ".js", ".jsx", ".ts", ".tsx")):
                count += 1
    return count


def _auto_train_model() -> bool:
    """Auto-train the ML model on the demo project if no model exists."""
    logger.info("No trained model found. Auto-training on demo_project...")
    try:
        import pandas as pd

        from .generate_labeled_data import main as gen_data_main
        from .ml import extract_features, train_model

        demo_dir = os.path.join(os.path.dirname(__file__), "..", "..", "demo_project")
        demo_dir = os.path.abspath(demo_dir)
        if not os.path.isdir(demo_dir):
            logger.warning(
                "Demo project not found at %s. Skipping auto-training.", demo_dir
            )
            return False
        labeled_csv = "labeled_findings.csv"
        gen_data_main.callback(demo_dir, labeled_csv)  # type: ignore[misc]
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


def _run_python_scan(path: str) -> List[Dict[str, Any]]:
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


def _run_js_scan(path: str) -> List[Dict[str, Any]]:
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


def _run_taint_analysis(path: str) -> List[Dict[str, Any]]:
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


def _score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
    type=click.Choice(["text", "json", "sarif", "html", "markdown"], case_sensitive=False),
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
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Only show findings at or above this severity level.",
)
@click.option(
    "--rules-dir",
    multiple=True,
    type=click.Path(exists=True),
    help="Additional directory of YAML rule files (may be repeated).",
)
@click.option(
    "--profile",
    type=click.Choice(["quick", "standard", "deep"], case_sensitive=False),
    default=None,
    help="Scan profile controlling analysis depth (default: standard).",
)
@click.option(
    "--save-baseline",
    type=click.Path(),
    default=None,
    help="Save current scan results as a baseline file for future differential scans.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    output_format: str,
    output_file: Optional[str],
    compact: bool,
    baseline: Optional[str],
    show_suppressed: bool,
    min_severity: Optional[str],
    rules_dir: tuple,
    profile: Optional[str],
    save_baseline: Optional[str],
) -> None:
    """Scan the given codebase for potential vulnerabilities."""
    if not os.path.exists(path):
        logger.error("Scan path not found: %s", path)
        sys.exit(EXIT_ERROR)

    scan_start = time.time()
    abs_path = os.path.abspath(path)

    # Resolve scan profile
    from .profiles import get_profile

    scan_profile = get_profile(profile)
    logger.info(
        "Starting scan of %s (format=%s, profile=%s)",
        abs_path, output_format, scan_profile.name,
    )

    # Load rule engine
    from .rules import RuleIndex, load_all_rules

    all_rules = load_all_rules(extra_dirs=list(rules_dir) if rules_dir else None)
    rule_index = RuleIndex(all_rules)
    logger.info("Loaded %d detection rules", len(rule_index))

    # Load suppression configuration
    from .suppression import IgnoreFile, apply_suppressions, load_baseline, save_baseline as _save_baseline

    ignore_file = IgnoreFile.from_project(abs_path)
    baseline_findings = load_baseline(baseline) if baseline else None

    # Auto-train if model is missing (only for deep profile)
    model_available = False
    if scan_profile.ml_scoring:
        model_available = os.path.exists(MODEL_PATH)
        if not model_available:
            model_available = _auto_train_model()

    # Run analyzers based on profile
    py_findings = _run_python_scan(path) if scan_profile.pattern_matching else []
    js_findings = _run_js_scan(path) if scan_profile.js_analysis else []
    interproc_findings = (
        _run_taint_analysis(path) if scan_profile.interprocedural_analysis else []
    )

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

    # Save baseline if requested (uses all findings before severity filtering)
    if save_baseline:
        _save_baseline(
            all_findings,
            output_path=save_baseline,
            scan_path=path,
            scan_duration=scan_duration,
            file_count=file_count,
        )
        click.echo(f"[VulnPredict] Baseline saved to {save_baseline} ({len(all_findings)} findings)")

    # Score findings with ML model (only if profile enables it and model available)
    if scan_profile.ml_scoring and model_available:
        scored_findings = _score_findings(active_findings)
    else:
        if scan_profile.ml_scoring:
            logger.info("No ML model available. Returning unscored findings.")
        else:
            logger.debug("ML scoring disabled by profile '%s'.", scan_profile.name)
        scored_findings = active_findings

    # Classify findings with severity and confidence
    from .severity import classify_finding, filter_by_severity, sort_by_severity

    scored_findings = [classify_finding(f) for f in scored_findings]
    scored_findings = sort_by_severity(scored_findings)

    # Apply minimum severity filter if requested
    if min_severity:
        pre_filter_count = len(scored_findings)
        scored_findings = filter_by_severity(scored_findings, min_severity)
        filtered_count = pre_filter_count - len(scored_findings)
        if filtered_count > 0:
            logger.info(
                "Filtered %d findings below %s severity.",
                filtered_count,
                min_severity,
            )

    # Determine which findings to output
    output_findings = scored_findings
    if show_suppressed:
        output_findings = scored_findings + suppressed_findings

    # --- Markdown output ---
    if output_format == "markdown":
        try:
            from .formatters.markdown import format_markdown, write_markdown

            if output_file:
                write_markdown(
                    output_findings,
                    scan_path=path,
                    output_path=output_file,
                    scan_duration=scan_duration,
                    file_count=file_count,
                    suppressed_count=len(suppressed_findings),
                )
                click.echo(f"[VulnPredict] Markdown report written to {output_file}")
            else:
                md_str = format_markdown(
                    output_findings,
                    scan_path=path,
                    scan_duration=scan_duration,
                    file_count=file_count,
                    suppressed_count=len(suppressed_findings),
                )
                click.echo(md_str)
        except Exception as exc:
            logger.error("Failed to generate Markdown output: %s", exc)
            logger.debug("Traceback:", exc_info=True)
            sys.exit(EXIT_ERROR)
        _print_suppression_summary(suppressed_findings)
        return

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
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        severity_colors = {
            "Critical": "red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
        }
        for finding in scored_findings:
            sev = finding.get("severity", "Low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            color = severity_colors.get(sev, "white")
            rule_id = finding.get("rule_id", "UNKNOWN")
            conf = finding.get("confidence", "Medium")
            score = finding.get("combined_score", finding.get("vuln_score", 0))
            name = finding.get("name", finding.get("file", "unknown"))
            desc = finding.get("rule_description", "")
            click.echo(
                click.style(
                    f"[{sev:8s}] [{rule_id}] (confidence={conf}, score={score:.3f}) "
                    f"{name}: {desc}",
                    fg=color,
                )
            )
        click.echo("\n=== Summary ===")
        for sev_name in ("Critical", "High", "Medium", "Low"):
            count = severity_counts.get(sev_name, 0)
            if count > 0:
                click.echo(f"  {sev_name:10s}: {count}")
        click.echo(f"  {'Total':10s}: {len(scored_findings)} findings")
        if min_severity:
            click.echo(f"  (filtered to {min_severity}+ severity)")
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


def _print_suppression_summary(suppressed_findings: List[Dict[str, Any]]) -> None:
    """Print a summary of suppressed findings by reason."""
    if not suppressed_findings:
        return
    reasons: Dict[str, int] = {}
    for f in suppressed_findings:
        reason = f.get("suppression_reason", "unknown")
        reasons[reason] = reasons.get(reason, 0) + 1
    click.echo(f"\n[VulnPredict] {len(suppressed_findings)} finding(s) suppressed:")
    for reason, count in sorted(reasons.items()):
        click.echo(f"  - {reason}: {count}")


@main.command()
@click.argument(
    "project_dir",
    default=".",
    type=click.Path(exists=True),
)
def init(project_dir: str) -> None:
    """Generate a default .vulnpredict.yml configuration file."""
    from .config import CONFIG_FILENAME, generate_default_config

    config_path = os.path.join(project_dir, CONFIG_FILENAME)
    if os.path.exists(config_path):
        click.echo(f"Configuration file already exists: {config_path}")
        if not click.confirm("Overwrite?"):
            click.echo("Aborted.")
            return
    try:
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write(generate_default_config())
        click.echo(f"[VulnPredict] Created {config_path}")
        click.echo("Edit the file to customise scan settings for your project.")
    except OSError as exc:
        logger.error("Failed to write config file: %s", exc)
        sys.exit(EXIT_ERROR)


@main.command()
@click.argument("csv_file")
def train(csv_file: str) -> None:
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
