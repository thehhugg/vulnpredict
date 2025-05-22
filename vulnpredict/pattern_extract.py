import json
import pandas as pd

def extract_patterns_from_nvd(json_file):
    """
    Extract affected products, CWE IDs, and descriptions from NVD CVE JSON data.
    Returns a pandas DataFrame.
    """
    with open(json_file, 'r') as f:
        data = json.load(f)
    records = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        description = cve.get('descriptions', [{}])[0].get('value', '')
        cwes = [p.get('value') for p in cve.get('weaknesses', [{}])[0].get('description', [])]
        products = []
        for conf in cve.get('configurations', []):
            for node in conf.get('nodes', []):
                for prod in node.get('cpeMatch', []):
                    products.append(prod.get('criteria'))
        records.append({
            'cve_id': cve_id,
            'description': description,
            'cwes': cwes,
            'products': products
        })
    return pd.DataFrame(records) 