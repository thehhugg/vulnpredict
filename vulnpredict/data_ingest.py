"""NVD CVE data ingestion module."""

import json
import os

import requests

from .logging_config import get_logger

logger = get_logger(__name__)


def fetch_nvd_cve_data(year, out_file):
    """
    Fetch CVE data from NVD for a given year and save to out_file (JSON).
    Requires NVD_API_KEY in environment for higher rate limits.
    """
    api_key = os.getenv("NVD_API_KEY")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = (
        f"{base_url}?pubStartDate={year}-01-01T00:00:00.000"
        f"&pubEndDate={year}-12-31T23:59:59.999"
    )
    headers = {"apiKey": api_key} if api_key else {}
    logger.info("Fetching NVD CVE data for year %d...", year)
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        with open(out_file, "w") as f:
            json.dump(resp.json(), f)
        logger.info("Saved NVD CVE data for %d to %s", year, out_file)
    except requests.RequestException as exc:
        logger.error("Failed to fetch NVD data for year %d: %s", year, exc)
        logger.debug("Traceback:", exc_info=True)
        raise
    except OSError as exc:
        logger.error("Failed to write NVD data to %s: %s", out_file, exc)
        raise
