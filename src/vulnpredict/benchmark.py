"""Benchmark evaluation framework for VulnPredict detection accuracy.

Provides a standardized way to measure precision, recall, F1 score,
and false positive rate against a curated dataset of labeled code samples.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Aggregated benchmark metrics."""

    total_samples: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    elapsed_seconds: float = 0.0
    per_type_results: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.total_samples
        correct = self.true_positives + self.true_negatives
        return correct / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "per_type_results": self.per_type_results,
        }


@dataclass
class BenchmarkSample:
    """A single benchmark code sample with ground truth."""

    code: str
    label: int  # 1 = vulnerable, 0 = safe
    vuln_type: str
    cwe: str = ""
    language: str = "python"
    source: str = ""


def load_benchmark_dataset(path: str) -> List[BenchmarkSample]:
    """Load a benchmark dataset from a CSV file.

    Expected CSV columns: code, label, type, cwe (optional),
    language (optional), source (optional).

    Args:
        path: Path to the CSV file.

    Returns:
        List of BenchmarkSample objects.
    """
    samples: List[BenchmarkSample] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append(BenchmarkSample(
                code=row.get("code", ""),
                label=int(row.get("label", 0)),
                vuln_type=row.get("type", "unknown"),
                cwe=row.get("cwe", ""),
                language=row.get("language", "python"),
                source=row.get("source", ""),
            ))
    return samples


def _scan_code_snippet(
    code: str,
    language: str,
    tmp_dir: Path,
) -> List[Dict[str, Any]]:
    """Scan a code snippet by writing it to a temp file and running analyzers.

    Args:
        code: Source code to scan.
        language: Programming language ("python" or "javascript").
        tmp_dir: Temporary directory for writing files.

    Returns:
        List of findings from the scan.
    """
    findings: List[Dict[str, Any]] = []

    if language == "python":
        filepath = tmp_dir / "benchmark_sample.py"
        filepath.write_text(code, encoding="utf-8")
        try:
            from vulnpredict.py_analyzer import analyze_python_file
            findings = analyze_python_file(str(filepath))
        except Exception as e:
            logger.debug("Python analysis error: %s", e)
    elif language in ("javascript", "js"):
        filepath = tmp_dir / "benchmark_sample.js"
        filepath.write_text(code, encoding="utf-8")
        try:
            from vulnpredict.js_analyzer import analyze_js_file
            findings = analyze_js_file(str(filepath))
        except Exception as e:
            logger.debug("JS analysis error: %s", e)

    return findings


def run_benchmark(
    dataset_path: str,
    output_path: Optional[str] = None,
) -> BenchmarkResult:
    """Run the benchmark evaluation against a labeled dataset.

    For each sample, runs VulnPredict's analyzers and compares the
    detection result against the ground truth label.

    Args:
        dataset_path: Path to the benchmark CSV dataset.
        output_path: Optional path to write detailed results JSON.

    Returns:
        BenchmarkResult with aggregated metrics.
    """
    import tempfile

    samples = load_benchmark_dataset(dataset_path)
    result = BenchmarkResult(total_samples=len(samples))

    start_time = time.time()
    detailed_results: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        for sample in samples:
            findings = _scan_code_snippet(
                sample.code, sample.language, tmp_path
            )
            detected = len(findings) > 0
            expected_vuln = sample.label == 1

            if detected and expected_vuln:
                result.true_positives += 1
                outcome = "TP"
            elif detected and not expected_vuln:
                result.false_positives += 1
                outcome = "FP"
            elif not detected and expected_vuln:
                result.false_negatives += 1
                outcome = "FN"
            else:
                result.true_negatives += 1
                outcome = "TN"

            # Track per-type results
            vtype = sample.vuln_type
            if vtype not in result.per_type_results:
                result.per_type_results[vtype] = {
                    "TP": 0, "FP": 0, "TN": 0, "FN": 0
                }
            result.per_type_results[vtype][outcome] += 1

            detailed_results.append({
                "code_preview": sample.code[:80],
                "label": sample.label,
                "type": sample.vuln_type,
                "detected": detected,
                "outcome": outcome,
                "findings_count": len(findings),
            })

    result.elapsed_seconds = time.time() - start_time

    if output_path:
        output = {
            "summary": result.to_dict(),
            "detailed_results": detailed_results,
        }
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        logger.info("Benchmark results written to %s", output_path)

    return result


def generate_benchmark_dataset(
    output_path: str,
    samples_per_type: int = 15,
    seed: int = 42,
) -> str:
    """Generate a curated benchmark dataset.

    Creates a balanced dataset with vulnerable and safe samples across
    multiple vulnerability types, suitable for evaluation.

    Args:
        output_path: Path to write the CSV dataset.
        samples_per_type: Number of samples per vulnerability type.
        seed: Random seed for reproducibility.

    Returns:
        Path to the generated dataset.
    """
    from vulnpredict.training_pipeline import (
        VULN_TEMPLATES,
        generate_synthetic_samples,
    )

    all_samples: List[Dict[str, Any]] = []
    for vuln_type in VULN_TEMPLATES:
        samples = generate_synthetic_samples(
            vuln_type, count=samples_per_type, seed=seed
        )
        for s in samples:
            s["language"] = "python"
            s["cwe"] = ""
        all_samples.extend(samples)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["code", "label", "type", "cwe", "language", "source", "variant"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_samples)

    logger.info("Benchmark dataset generated: %s (%d samples)", output_path, len(all_samples))
    return output_path
