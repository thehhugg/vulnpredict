"""Vulnerability database client using the OSV.dev API.

Provides real vulnerability lookups for Python (PyPI) and JavaScript (npm)
packages, replacing the previous ``check_vulnerable_stub()`` that always
returned ``False``.

Features:
- OSV.dev batch and single-package query support
- Local JSON file cache with configurable TTL (default 24 h)
- Graceful degradation on network/API errors
- Returns severity, CVE IDs, advisory URLs, and affected version ranges
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from .logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OSV_API_URL = "https://api.osv.dev/v1"
OSV_QUERY_ENDPOINT = f"{OSV_API_URL}/query"
OSV_BATCH_ENDPOINT = f"{OSV_API_URL}/querybatch"

DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".vulnpredict", "cache")
DEFAULT_CACHE_TTL = 86400  # 24 hours in seconds
REQUEST_TIMEOUT = 15  # seconds
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds; doubles each retry


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class VulnCache:
    """Simple JSON file-based cache for vulnerability lookups.

    Each cache entry is stored as a separate JSON file keyed by a hash of
    (ecosystem, package, version).  Entries expire after *ttl* seconds.
    """

    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, ttl: int = DEFAULT_CACHE_TTL):
        self.cache_dir = cache_dir
        self.ttl = ttl
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def _cache_key(ecosystem: str, package: str, version: str) -> str:
        raw = f"{ecosystem}:{package}:{version}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def get(self, ecosystem: str, package: str, version: str) -> Optional[List[Dict]]:
        """Return cached vulnerabilities or ``None`` if not cached / expired."""
        key = self._cache_key(ecosystem, package, version)
        path = self._path(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                entry = json.load(f)
            if time.time() - entry.get("ts", 0) > self.ttl:
                logger.debug("Cache expired for %s:%s@%s", ecosystem, package, version)
                return None
            return list(entry.get("vulns", []))
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Cache read error for %s:%s@%s: %s", ecosystem, package, version, exc)
            return None

    def put(self, ecosystem: str, package: str, version: str, vulns: List[Dict]) -> None:
        """Store vulnerability results in the cache."""
        key = self._cache_key(ecosystem, package, version)
        path = self._path(key)
        try:
            with open(path, "w") as f:
                json.dump({"ts": time.time(), "vulns": vulns}, f)
            # Restrict cache file to owner-only read/write
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            logger.debug("Cache write error for %s:%s@%s: %s", ecosystem, package, version, exc)

    def clear(self) -> int:
        """Remove all cache entries.  Returns the number of files removed."""
        count = 0
        if os.path.isdir(self.cache_dir):
            for fname in os.listdir(self.cache_dir):
                if fname.endswith(".json"):
                    try:
                        os.remove(os.path.join(self.cache_dir, fname))
                        count += 1
                    except OSError:
                        pass
        return count


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------


def _parse_severity(vuln: Dict) -> Tuple[str, Optional[float]]:
    """Extract severity label and CVSS score from an OSV vulnerability."""
    severity_list = vuln.get("severity", [])
    for sev in severity_list:
        stype = sev.get("type", "")
        score_str = sev.get("score", "")
        if stype.startswith("CVSS"):
            # Try to extract the numeric score from the vector string
            # CVSS vectors look like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # The numeric score is not in the vector; OSV sometimes provides it separately
            pass
    # Fallback: derive from database_specific or ecosystem_specific
    db_specific = vuln.get("database_specific", {})
    cvss_score = db_specific.get("cvss_score") or db_specific.get("score")
    if isinstance(cvss_score, (int, float)):
        if cvss_score >= 9.0:
            return "critical", float(cvss_score)
        if cvss_score >= 7.0:
            return "high", float(cvss_score)
        if cvss_score >= 4.0:
            return "medium", float(cvss_score)
        return "low", float(cvss_score)

    # Use severity from ecosystem_specific
    eco_sev = db_specific.get("severity", "").upper()
    if eco_sev in ("CRITICAL",):
        return "critical", None
    if eco_sev in ("HIGH",):
        return "high", None
    if eco_sev in ("MODERATE", "MEDIUM"):
        return "medium", None
    if eco_sev in ("LOW",):
        return "low", None

    return "unknown", None


def _parse_vuln(vuln: Dict) -> Dict[str, Any]:
    """Convert an OSV vulnerability record to a VulnPredict finding dict."""
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", vuln.get("details", "No description available"))[:200]
    aliases = vuln.get("aliases", [])
    cve_ids = [a for a in aliases if a.startswith("CVE-")]
    severity_label, cvss_score = _parse_severity(vuln)

    references = vuln.get("references", [])
    advisory_urls = [r.get("url") for r in references if r.get("url")][:3]

    affected_ranges = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            introduced = None
            fixed = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if introduced or fixed:
                affected_ranges.append({"introduced": introduced, "fixed": fixed})

    return {
        "vuln_id": vuln_id,
        "summary": summary,
        "cve_ids": cve_ids,
        "severity": severity_label,
        "cvss_score": cvss_score,
        "advisory_urls": advisory_urls,
        "affected_ranges": affected_ranges,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_package_vulnerabilities(
    ecosystem: str,
    package: str,
    version: str,
    cache: Optional[VulnCache] = None,
) -> List[Dict[str, Any]]:
    """Query OSV.dev for known vulnerabilities in a specific package version.

    Parameters
    ----------
    ecosystem : str
        Package ecosystem, e.g. ``"PyPI"`` or ``"npm"``.
    package : str
        Package name.
    version : str
        Exact version string.
    cache : VulnCache, optional
        Cache instance.  If ``None``, a default cache is used.

    Returns
    -------
    list of dict
        Each dict contains ``vuln_id``, ``summary``, ``cve_ids``,
        ``severity``, ``cvss_score``, ``advisory_urls``, and
        ``affected_ranges``.
    """
    if cache is None:
        cache = VulnCache()

    # Check cache first
    cached = cache.get(ecosystem, package, version)
    if cached is not None:
        logger.debug("Cache hit for %s:%s@%s (%d vulns)", ecosystem, package, version, len(cached))
        return cached

    # Query OSV.dev
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }

    data = _request_with_retry(OSV_QUERY_ENDPOINT, payload, f"{ecosystem}:{package}@{version}")
    if data is None:
        return []

    raw_vulns = data.get("vulns", [])
    parsed = [_parse_vuln(v) for v in raw_vulns]

    # Cache the result
    cache.put(ecosystem, package, version, parsed)
    logger.info(
        "Found %d vulnerabilities for %s:%s@%s",
        len(parsed),
        ecosystem,
        package,
        version,
    )
    return parsed


def _request_with_retry(
    url: str, payload: dict, label: str, timeout: int = REQUEST_TIMEOUT
) -> Optional[dict]:
    """POST to *url* with exponential backoff on transient errors.

    Returns the parsed JSON response on success, or ``None`` on failure.
    """
    for attempt in range(MAX_RETRIES):
        try:
            logger.debug("Querying OSV.dev for %s (attempt %d/%d)", label, attempt + 1, MAX_RETRIES)
            resp = requests.post(url, json=payload, timeout=timeout)
            # Retry on 429 and 5xx
            if resp.status_code == 429 or resp.status_code >= 500:
                wait = BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "OSV.dev returned %d for %s; retrying in %.1fs",
                    resp.status_code, label, wait,
                )
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return dict(resp.json())
        except requests.exceptions.Timeout:
            wait = BACKOFF_BASE * (2 ** attempt)
            logger.warning("OSV.dev request timed out for %s (attempt %d/%d)", label, attempt + 1, MAX_RETRIES)
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            continue
        except requests.exceptions.ConnectionError:
            wait = BACKOFF_BASE * (2 ** attempt)
            logger.warning("OSV.dev connection failed for %s (attempt %d/%d)", label, attempt + 1, MAX_RETRIES)
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            continue
        except requests.exceptions.HTTPError as exc:
            logger.warning("OSV.dev HTTP error for %s: %s", label, exc)
            return None
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("OSV.dev response parse error for %s: %s", label, exc)
            return None
    logger.error("OSV.dev request failed after %d retries for %s", MAX_RETRIES, label)
    return None


def check_package_batch(
    queries: List[Dict[str, str]],
    cache: Optional[VulnCache] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Batch-query OSV.dev for multiple packages.

    Parameters
    ----------
    queries : list of dict
        Each dict must have ``ecosystem``, ``package``, and ``version`` keys.
    cache : VulnCache, optional
        Cache instance.

    Returns
    -------
    dict
        Mapping of ``"ecosystem:package@version"`` to list of vulnerability dicts.
    """
    if cache is None:
        cache = VulnCache()

    results = {}
    uncached_queries = []
    uncached_keys = []

    for q in queries:
        eco = q["ecosystem"]
        pkg = q["package"]
        ver = q["version"]
        key = f"{eco}:{pkg}@{ver}"

        cached = cache.get(eco, pkg, ver)
        if cached is not None:
            results[key] = cached
        else:
            uncached_queries.append(
                {"version": ver, "package": {"name": pkg, "ecosystem": eco}}
            )
            uncached_keys.append((key, eco, pkg, ver))

    if not uncached_queries:
        return results

    # OSV batch API with retry
    data = _request_with_retry(
        OSV_BATCH_ENDPOINT,
        {"queries": uncached_queries},
        f"batch({len(uncached_queries)} packages)",
        timeout=REQUEST_TIMEOUT * 2,
    )
    if data is None:
        # Fall back to individual queries
        logger.warning("Batch query failed; falling back to individual queries")
        for key, eco, pkg, ver in uncached_keys:
            results[key] = check_package_vulnerabilities(eco, pkg, ver, cache=cache)
        return results

    batch_results = data.get("results", [])
    for i, (key, eco, pkg, ver) in enumerate(uncached_keys):
        if i < len(batch_results):
            raw_vulns = batch_results[i].get("vulns", [])
            parsed = [_parse_vuln(v) for v in raw_vulns]
        else:
            parsed = []
        cache.put(eco, pkg, ver, parsed)
        results[key] = parsed

    return results


def check_vulnerable(package: str, version: str, ecosystem: str = "PyPI") -> Tuple[bool, Optional[Dict]]:
    """Drop-in replacement for ``check_vulnerable_stub()``.

    Returns
    -------
    tuple of (bool, dict or None)
        ``(True, finding_dict)`` if vulnerabilities found, else ``(False, None)``.
    """
    vulns = check_package_vulnerabilities(ecosystem, package, version)
    if not vulns:
        return False, None

    # Return the most severe vulnerability
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", "unknown"), 99))
    most_severe = vulns_sorted[0]

    return True, {
        "type": "vulnerable_dependency",
        "package": package,
        "version": version,
        "vuln_id": most_severe["vuln_id"],
        "cve_ids": most_severe["cve_ids"],
        "severity": most_severe["severity"],
        "cvss_score": most_severe["cvss_score"],
        "summary": most_severe["summary"],
        "advisory_urls": most_severe["advisory_urls"],
        "total_vulnerabilities": len(vulns),
    }
