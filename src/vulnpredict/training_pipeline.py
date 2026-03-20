"""Automated training data pipeline.

Orchestrates the full pipeline: NVD fetch -> pattern extraction ->
synthetic sample generation -> labeled dataset creation.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import random
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE -> VulnPredict rule mapping
# ---------------------------------------------------------------------------

CWE_TO_RULE: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "rule_id": "VP-PY-001",
        "type": "sql_injection",
        "severity": "critical",
    },
    "CWE-78": {
        "rule_id": "VP-PY-002",
        "type": "command_injection",
        "severity": "critical",
    },
    "CWE-79": {
        "rule_id": "VP-PY-003",
        "type": "xss",
        "severity": "high",
    },
    "CWE-502": {
        "rule_id": "VP-PY-004",
        "type": "deserialization",
        "severity": "critical",
    },
    "CWE-918": {
        "rule_id": "VP-PY-005",
        "type": "ssrf",
        "severity": "high",
    },
    "CWE-327": {
        "rule_id": "VP-PY-006",
        "type": "weak_crypto",
        "severity": "medium",
    },
    "CWE-798": {
        "rule_id": "VP-PY-007",
        "type": "hardcoded_credentials",
        "severity": "high",
    },
    "CWE-22": {
        "rule_id": "VP-PY-008",
        "type": "path_traversal",
        "severity": "high",
    },
    "CWE-611": {
        "rule_id": "VP-PY-009",
        "type": "xxe",
        "severity": "high",
    },
    "CWE-295": {
        "rule_id": "VP-PY-010",
        "type": "insecure_tls",
        "severity": "high",
    },
}

# ---------------------------------------------------------------------------
# Synthetic code templates by vulnerability type
# ---------------------------------------------------------------------------

VULN_TEMPLATES: Dict[str, List[str]] = {
    "sql_injection": [
        textwrap.dedent("""\
            def get_user(username):
                query = "SELECT * FROM users WHERE name = '" + username + "'"
                cursor.execute(query)
                return cursor.fetchone()
        """),
        textwrap.dedent("""\
            def search_products(term):
                sql = f"SELECT * FROM products WHERE name LIKE '%{{term}}%'"
                db.execute(sql)
                return db.fetchall()
        """),
        textwrap.dedent("""\
            def delete_record(record_id):
                query = "DELETE FROM records WHERE id = %s" % record_id
                conn.execute(query)
        """),
    ],
    "command_injection": [
        textwrap.dedent("""\
            def ping_host(host):
                import os
                os.system("ping -c 1 " + host)
        """),
        textwrap.dedent("""\
            def convert_file(filename):
                import subprocess
                subprocess.call("convert " + filename + " output.pdf", shell=True)
        """),
    ],
    "xss": [
        textwrap.dedent("""\
            def render_greeting(name):
                return "<h1>Hello, " + name + "</h1>"
        """),
        textwrap.dedent("""\
            def show_comment(comment):
                return f"<div class='comment'>{{comment}}</div>"
        """),
    ],
    "deserialization": [
        textwrap.dedent("""\
            def load_data(data):
                import pickle
                return pickle.loads(data)
        """),
        textwrap.dedent("""\
            def process_config(config_str):
                import yaml
                return yaml.load(config_str)
        """),
    ],
    "ssrf": [
        textwrap.dedent("""\
            def fetch_url(url):
                import requests
                return requests.get(url).text
        """),
        textwrap.dedent("""\
            def proxy_request(target):
                import urllib.request
                return urllib.request.urlopen(target).read()
        """),
    ],
    "weak_crypto": [
        textwrap.dedent("""\
            def hash_password(password):
                import hashlib
                return hashlib.md5(password.encode()).hexdigest()
        """),
        textwrap.dedent("""\
            def encrypt_data(data, key):
                from Crypto.Cipher import DES
                cipher = DES.new(key, DES.MODE_ECB)
                return cipher.encrypt(data)
        """),
    ],
    "path_traversal": [
        textwrap.dedent("""\
            def read_file(filename):
                path = "/var/data/" + filename
                with open(path) as f:
                    return f.read()
        """),
    ],
}

SAFE_TEMPLATES: Dict[str, List[str]] = {
    "sql_injection": [
        textwrap.dedent("""\
            def get_user(username):
                cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
                return cursor.fetchone()
        """),
    ],
    "command_injection": [
        textwrap.dedent("""\
            def ping_host(host):
                import subprocess
                subprocess.run(["ping", "-c", "1", host], check=True)
        """),
    ],
    "xss": [
        textwrap.dedent("""\
            def render_greeting(name):
                from markupsafe import escape
                return f"<h1>Hello, {{escape(name)}}</h1>"
        """),
    ],
    "deserialization": [
        textwrap.dedent("""\
            def load_data(data):
                import json
                return json.loads(data)
        """),
    ],
    "ssrf": [
        textwrap.dedent("""\
            def fetch_url(url):
                import requests
                ALLOWED = ["https://api.example.com"]
                if url not in ALLOWED:
                    raise ValueError("URL not allowed")
                return requests.get(url).text
        """),
    ],
    "weak_crypto": [
        textwrap.dedent("""\
            def hash_password(password):
                import hashlib
                salt = os.urandom(32)
                return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        """),
    ],
    "path_traversal": [
        textwrap.dedent("""\
            def read_file(filename):
                import os
                base = "/var/data"
                path = os.path.realpath(os.path.join(base, filename))
                if not path.startswith(base):
                    raise ValueError("Path traversal detected")
                with open(path) as f:
                    return f.read()
        """),
    ],
}


def map_cwe_to_rule(cwe_id: str) -> Optional[Dict[str, str]]:
    """Map a CWE identifier to a VulnPredict rule.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-89").

    Returns:
        Dict with rule_id, type, and severity, or None if unmapped.
    """
    return CWE_TO_RULE.get(cwe_id)


def generate_synthetic_samples(
    vuln_type: str,
    count: int = 10,
    seed: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate synthetic code samples for a vulnerability type.

    Creates a mix of vulnerable (label=1) and safe (label=0) samples
    using predefined templates with minor variations.

    Args:
        vuln_type: Vulnerability type (e.g., "sql_injection").
        count: Total number of samples to generate.
        seed: Random seed for reproducibility.

    Returns:
        List of sample dicts with 'code', 'label', 'type', and 'source' keys.
    """
    if seed is not None:
        random.seed(seed)

    vuln_templates = VULN_TEMPLATES.get(vuln_type, [])
    safe_templates = SAFE_TEMPLATES.get(vuln_type, [])

    if not vuln_templates:
        logger.warning("No templates for vulnerability type: %s", vuln_type)
        return []

    samples: List[Dict[str, Any]] = []
    vuln_count = count // 2
    safe_count = count - vuln_count

    # Generate vulnerable samples
    for i in range(vuln_count):
        template = random.choice(vuln_templates)
        samples.append({
            "code": template.strip(),
            "label": 1,
            "type": vuln_type,
            "source": "synthetic",
            "variant": i,
        })

    # Generate safe samples
    for i in range(safe_count):
        if safe_templates:
            template = random.choice(safe_templates)
        else:
            template = f"# Safe code placeholder for {vuln_type}\ndef safe_func(): pass"
        samples.append({
            "code": template.strip(),
            "label": 0,
            "type": vuln_type,
            "source": "synthetic",
            "variant": i,
        })

    random.shuffle(samples)
    return samples


def generate_full_dataset(
    output_path: str,
    samples_per_type: int = 20,
    seed: int = 42,
) -> Dict[str, Any]:
    """Generate a complete labeled training dataset.

    Creates synthetic samples for all known vulnerability types and
    writes them to a CSV file.

    Args:
        output_path: Path to write the CSV dataset.
        samples_per_type: Number of samples per vulnerability type.
        seed: Random seed for reproducibility.

    Returns:
        Dict with metadata about the generated dataset.
    """
    all_samples: List[Dict[str, Any]] = []

    for vuln_type in VULN_TEMPLATES:
        samples = generate_synthetic_samples(
            vuln_type, count=samples_per_type, seed=seed
        )
        all_samples.extend(samples)

    # Write to CSV
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["code", "label", "type", "source", "variant"]
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_samples)

    metadata = {
        "total_samples": len(all_samples),
        "vuln_types": list(VULN_TEMPLATES.keys()),
        "samples_per_type": samples_per_type,
        "output_path": str(output),
        "generated_at": datetime.utcnow().isoformat(),
        "seed": seed,
        "label_distribution": {
            "vulnerable": sum(1 for s in all_samples if s["label"] == 1),
            "safe": sum(1 for s in all_samples if s["label"] == 0),
        },
    }

    # Write metadata sidecar
    meta_path = output.with_suffix(".meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(
        "Generated %d samples (%d types) -> %s",
        len(all_samples),
        len(VULN_TEMPLATES),
        output_path,
    )
    return metadata


def run_pipeline(
    output_dir: str = "training_data",
    samples_per_type: int = 20,
    seed: int = 42,
) -> Dict[str, Any]:
    """Run the full training data pipeline.

    Steps:
    1. Map CWE categories to VulnPredict rules
    2. Generate synthetic code samples for each vulnerability type
    3. Create a versioned, labeled CSV dataset

    Args:
        output_dir: Directory to write output files.
        samples_per_type: Number of samples per vulnerability type.
        seed: Random seed for reproducibility.

    Returns:
        Pipeline execution metadata.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Step 1: Write CWE mapping reference
    mapping_path = out / "cwe_mapping.json"
    with open(mapping_path, "w", encoding="utf-8") as f:
        json.dump(CWE_TO_RULE, f, indent=2)
    logger.info("CWE mapping written to %s", mapping_path)

    # Step 2: Generate dataset
    dataset_path = str(out / "training_dataset.csv")
    metadata = generate_full_dataset(
        dataset_path, samples_per_type=samples_per_type, seed=seed
    )

    # Step 3: Write pipeline summary
    summary = {
        "pipeline_version": "1.0.0",
        "cwe_mapping_path": str(mapping_path),
        "dataset_metadata": metadata,
        "run_at": datetime.utcnow().isoformat(),
    }
    summary_path = out / "pipeline_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Pipeline complete. Summary: %s", summary_path)
    return summary
