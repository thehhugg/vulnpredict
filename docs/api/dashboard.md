# Dashboard API Reference

The VulnPredict Dashboard provides a REST API for storing and querying scan results. It uses SQLite for storage and requires no external database setup.

## Starting the Server

```bash
uvicorn vulnpredict.dashboard.app:app --host 0.0.0.0 --port 8000
```

## Authentication

If the `VULNPREDICT_API_KEY` environment variable is set, all API requests must include a valid API key in the `X-API-Key` header. If the variable is not set, authentication is disabled.

```bash
export VULNPREDICT_API_KEY=your-secret-key
curl -H "X-API-Key: your-secret-key" http://localhost:8000/api/scans
```

## Endpoints

### Health Check

**GET** `/api/health`

Returns the server status. This endpoint does not require authentication.

### Submit a Scan

**POST** `/api/scans`

Submit scan results for storage. The request body must include the scan path and an array of findings.

```json
{
  "scan_path": "/path/to/project",
  "findings": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "file": "app.py",
      "line": 42,
      "message": "SQL injection via string concatenation",
      "rule_id": "VP-PY-001",
      "cwe": "CWE-89"
    }
  ],
  "files_scanned": 25,
  "scan_duration": 1.5
}
```

### List Scans

**GET** `/api/scans?page=1&per_page=20`

Returns a paginated list of all scans, ordered by creation date (newest first).

### Get Scan Details

**GET** `/api/scans/{scan_id}`

Returns the details of a specific scan including severity counts.

### Get Findings

**GET** `/api/scans/{scan_id}/findings?severity=critical&type=sql_injection&page=1&per_page=50`

Returns findings for a specific scan with optional filtering by severity and type.

### Delete a Scan

**DELETE** `/api/scans/{scan_id}`

Deletes a scan and all associated findings.

### Aggregate Statistics

**GET** `/api/stats`

Returns aggregate statistics across all scans, including severity distribution, type distribution, and recent scan history.
