import os
import requests
import json

def fetch_nvd_cve_data(year, out_file):
    """
    Fetch CVE data from NVD for a given year and save to out_file (JSON).
    Requires NVD_API_KEY in environment for higher rate limits.
    """
    api_key = os.getenv('NVD_API_KEY')
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.999'
    headers = {'apiKey': api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        with open(out_file, 'w') as f:
            json.dump(resp.json(), f)
        print(f"[VulnPredict] Saved NVD CVE data for {year} to {out_file}")
    except Exception as e:
        print(f"[VulnPredict] Error fetching NVD data: {e}") 