from __future__ import annotations

from typing import Any, Dict

import click
import pandas as pd

from .interprocedural_taint import analyze_project as analyze_interprocedural_taint
from .js_analyzer import analyze_js_project
from .logging_config import get_logger
from .py_analyzer import analyze_python_project

logger = get_logger(__name__)


def auto_label(finding: Dict[str, Any]) -> int:
    # Heuristic: label as vulnerable if dangerous_calls, high complexity, high nesting, or interprocedural taint
    if (
        finding.get("dangerous_calls")
        or finding.get("cyclomatic_complexity", 0) > 10
        or finding.get("max_nesting_depth", 0) > 5
    ):
        return 1
    if finding.get("type") == "interprocedural_taint":
        return 1
    return 0


@click.command()
@click.argument("code_dir")
@click.argument("output_csv")
def main(code_dir: str, output_csv: str) -> None:
    """
    Analyze CODE_DIR, label findings, and save to OUTPUT_CSV for ML training.
    """
    py_findings = analyze_python_project(code_dir)
    js_findings = analyze_js_project(code_dir)
    interproc_findings = analyze_interprocedural_taint(code_dir)
    all_findings = py_findings + js_findings + interproc_findings
    for f in all_findings:
        f["label"] = auto_label(f)
    df = pd.DataFrame(all_findings)
    df.to_csv(output_csv, index=False)
    logger.info("Labeled data saved to %s (%d findings)", output_csv, len(all_findings))


if __name__ == "__main__":
    main()
