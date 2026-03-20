"""Performance benchmarking for VulnPredict scan operations.

Generates synthetic projects of varying sizes and measures scan time
against defined performance targets.
"""

from __future__ import annotations

import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Performance targets (seconds)
TARGETS: Dict[str, Dict[str, float]] = {
    "small_quick": {"files": 50, "target_seconds": 5.0, "profile": "quick"},
    "small_standard": {"files": 50, "target_seconds": 30.0, "profile": "standard"},
    "medium_quick": {"files": 500, "target_seconds": 30.0, "profile": "quick"},
    "medium_standard": {"files": 500, "target_seconds": 180.0, "profile": "standard"},
}


@dataclass
class PerfResult:
    """Result of a single performance benchmark run."""

    scenario: str
    file_count: int
    profile: str
    elapsed_seconds: float
    target_seconds: float
    passed: bool
    files_per_second: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario,
            "file_count": self.file_count,
            "profile": self.profile,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "target_seconds": self.target_seconds,
            "passed": self.passed,
            "files_per_second": round(self.files_per_second, 1),
        }


def generate_synthetic_project(
    output_dir: str,
    num_python_files: int = 30,
    num_js_files: int = 15,
    num_go_files: int = 5,
    lines_per_file: int = 50,
    seed: int = 42,
) -> str:
    """Generate a synthetic project with source files for benchmarking.

    Args:
        output_dir: Directory to create the project in.
        num_python_files: Number of Python files to generate.
        num_js_files: Number of JavaScript files to generate.
        num_go_files: Number of Go files to generate.
        lines_per_file: Average lines per file.
        seed: Random seed for reproducibility.

    Returns:
        Path to the generated project directory.
    """
    random.seed(seed)
    project = Path(output_dir)
    project.mkdir(parents=True, exist_ok=True)

    # Python files
    py_snippets = [
        "import os\nimport sys\nimport json\n",
        "def process_data(data):\n    result = []\n    for item in data:\n        result.append(item.strip())\n    return result\n",
        "class DataHandler:\n    def __init__(self, config):\n        self.config = config\n\n    def handle(self, request):\n        return self.config.get('default', None)\n",
        "def validate_input(value):\n    if not isinstance(value, str):\n        raise TypeError('Expected string')\n    return value.strip()\n",
        "# Some vulnerable patterns for detection\ndef query_db(user_id):\n    sql = 'SELECT * FROM users WHERE id = ' + user_id\n    return execute(sql)\n",
        "def run_command(cmd):\n    import subprocess\n    subprocess.run(['echo', cmd], check=True)\n",
    ]

    for i in range(num_python_files):
        subdir = project / f"pkg_{i // 10}"
        subdir.mkdir(parents=True, exist_ok=True)
        filepath = subdir / f"module_{i}.py"
        content = random.choice(py_snippets)
        # Pad to target line count
        padding = "\n".join(
            f"# Line {j}" for j in range(lines_per_file - content.count("\n"))
        )
        filepath.write_text(content + "\n" + padding, encoding="utf-8")

    # JavaScript files
    js_snippets = [
        "const express = require('express');\nconst app = express();\n",
        "function processRequest(req, res) {\n  const data = req.body;\n  res.json({ status: 'ok', data });\n}\n",
        "// Potentially vulnerable\nfunction renderPage(userInput) {\n  document.innerHTML = userInput;\n}\n",
    ]

    for i in range(num_js_files):
        subdir = project / f"src_{i // 10}"
        subdir.mkdir(parents=True, exist_ok=True)
        filepath = subdir / f"handler_{i}.js"
        content = random.choice(js_snippets)
        padding = "\n".join(
            f"// Line {j}" for j in range(lines_per_file - content.count("\n"))
        )
        filepath.write_text(content + "\n" + padding, encoding="utf-8")

    # Go files
    go_snippets = [
        'package main\n\nimport "fmt"\n\nfunc main() {\n\tfmt.Println("hello")\n}\n',
        'package main\n\nimport "net/http"\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tw.Write([]byte("ok"))\n}\n',
    ]

    for i in range(num_go_files):
        filepath = project / f"cmd_{i}.go"
        content = random.choice(go_snippets)
        padding = "\n".join(
            f"// Line {j}" for j in range(lines_per_file - content.count("\n"))
        )
        filepath.write_text(content + "\n" + padding, encoding="utf-8")

    total = num_python_files + num_js_files + num_go_files
    logger.info("Generated %d files in %s", total, output_dir)
    return str(project)


def _run_scan(project_path: str, profile: str = "quick") -> float:
    """Run a VulnPredict scan and return elapsed time.

    Args:
        project_path: Path to the project to scan.
        profile: Scan profile to use.

    Returns:
        Elapsed time in seconds.
    """
    from vulnpredict.py_analyzer import analyze_python_project
    from vulnpredict.js_analyzer import analyze_js_file

    start = time.perf_counter()

    # Scan Python files
    py_files = list(Path(project_path).rglob("*.py"))
    findings = analyze_python_project(project_path) if py_files else []

    # Scan JS files
    js_files = list(Path(project_path).rglob("*.js"))
    for js_file in js_files:
        try:
            findings.extend(analyze_js_file(str(js_file)))
        except Exception:
            pass

    # Scan Go files (if available)
    go_files = list(Path(project_path).rglob("*.go"))
    if go_files:
        try:
            from vulnpredict.go_analyzer import scan_go_file
            for go_file in go_files:
                findings.extend(scan_go_file(str(go_file)))
        except ImportError:
            pass

    elapsed = time.perf_counter() - start
    return elapsed


def run_perf_benchmarks(
    output_path: Optional[str] = None,
    scenarios: Optional[List[str]] = None,
) -> List[PerfResult]:
    """Run performance benchmarks against defined targets.

    Args:
        output_path: Optional path to write results JSON.
        scenarios: Optional list of scenario names to run (default: all).

    Returns:
        List of PerfResult objects.
    """
    import tempfile

    if scenarios is None:
        scenarios = list(TARGETS.keys())

    results: List[PerfResult] = []

    for scenario_name in scenarios:
        if scenario_name not in TARGETS:
            logger.warning("Unknown scenario: %s", scenario_name)
            continue

        target = TARGETS[scenario_name]
        file_count = int(target["files"])
        target_seconds = target["target_seconds"]
        profile = str(target["profile"])

        # Calculate file distribution (60% Python, 30% JS, 10% Go)
        num_py = int(file_count * 0.6)
        num_js = int(file_count * 0.3)
        num_go = file_count - num_py - num_js

        with tempfile.TemporaryDirectory() as tmp_dir:
            project_path = generate_synthetic_project(
                tmp_dir,
                num_python_files=num_py,
                num_js_files=num_js,
                num_go_files=num_go,
            )

            elapsed = _run_scan(project_path, profile=profile)

        passed = elapsed <= target_seconds
        fps = file_count / elapsed if elapsed > 0 else 0

        result = PerfResult(
            scenario=scenario_name,
            file_count=file_count,
            profile=profile,
            elapsed_seconds=elapsed,
            target_seconds=target_seconds,
            passed=passed,
            files_per_second=fps,
        )
        results.append(result)

        status = "PASS" if passed else "FAIL"
        logger.info(
            "[%s] %s: %.2fs / %.1fs target (%.0f files/s)",
            status, scenario_name, elapsed, target_seconds, fps,
        )

    if output_path:
        output = {
            "results": [r.to_dict() for r in results],
            "all_passed": all(r.passed for r in results),
        }
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

    return results
