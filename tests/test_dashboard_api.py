"""Tests for the VulnPredict Dashboard FastAPI backend."""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from vulnpredict.dashboard.app import create_app
from vulnpredict.dashboard.models import Database


@pytest.fixture()
def db_path(tmp_path: Any) -> str:
    """Provide a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture()
def db(db_path: str) -> Database:
    """Provide a fresh Database instance."""
    return Database(db_path=db_path)


@pytest.fixture()
def client(db_path: str) -> TestClient:
    """Provide a test client with a fresh database."""
    os.environ.pop("VULNPREDICT_API_KEY", None)
    app = create_app(db_path=db_path)
    return TestClient(app)


@pytest.fixture()
def sample_scan() -> Dict[str, Any]:
    """Provide a sample scan submission payload."""
    return {
        "scan_path": "/home/user/project",
        "findings": [
            {
                "type": "sql_injection",
                "severity": "critical",
                "file": "app.py",
                "line": 42,
                "message": "SQL injection via string concatenation",
                "rule_id": "VP-PY-001",
                "cwe": "CWE-89",
            },
            {
                "type": "xss",
                "severity": "high",
                "file": "views.py",
                "line": 15,
                "message": "Cross-site scripting vulnerability",
            },
            {
                "type": "hardcoded_secret",
                "severity": "medium",
                "file": "config.py",
                "line": 3,
                "message": "Hardcoded API key",
            },
        ],
        "files_scanned": 25,
        "scan_duration": 1.5,
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_health(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /api/scans
# ---------------------------------------------------------------------------


class TestCreateScan:
    def test_create_scan(self, client: TestClient, sample_scan: Dict[str, Any]) -> None:
        resp = client.post("/api/scans", json=sample_scan)
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["scan_path"] == "/home/user/project"
        assert data["total_findings"] == 3
        assert data["critical_count"] == 1
        assert data["high_count"] == 1
        assert data["medium_count"] == 1

    def test_create_scan_empty_findings(self, client: TestClient) -> None:
        resp = client.post(
            "/api/scans",
            json={"scan_path": "/empty", "findings": []},
        )
        assert resp.status_code == 201
        assert resp.json()["total_findings"] == 0

    def test_create_scan_with_metadata(self, client: TestClient) -> None:
        resp = client.post(
            "/api/scans",
            json={
                "scan_path": "/project",
                "findings": [],
                "metadata": {"branch": "main", "commit": "abc123"},
            },
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# GET /api/scans
# ---------------------------------------------------------------------------


class TestListScans:
    def test_list_empty(self, client: TestClient) -> None:
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["scans"] == []

    def test_list_with_scans(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        client.post("/api/scans", json=sample_scan)
        client.post("/api/scans", json=sample_scan)
        resp = client.get("/api/scans")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["scans"]) == 2

    def test_pagination(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        for _ in range(5):
            client.post("/api/scans", json=sample_scan)
        resp = client.get("/api/scans?page=1&per_page=2")
        data = resp.json()
        assert data["total"] == 5
        assert len(data["scans"]) == 2
        assert data["pages"] == 3


# ---------------------------------------------------------------------------
# GET /api/scans/{id}
# ---------------------------------------------------------------------------


class TestGetScan:
    def test_get_scan(self, client: TestClient, sample_scan: Dict[str, Any]) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == scan_id

    def test_get_scan_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/scans/{id}/findings
# ---------------------------------------------------------------------------


class TestGetFindings:
    def test_get_findings(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.get(f"/api/scans/{scan_id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 3

    def test_filter_by_severity(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.get(f"/api/scans/{scan_id}/findings?severity=critical")
        data = resp.json()
        assert data["total"] == 1
        assert data["findings"][0]["severity"] == "critical"

    def test_filter_by_type(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.get(f"/api/scans/{scan_id}/findings?type=xss")
        data = resp.json()
        assert data["total"] == 1

    def test_findings_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/scans/nonexistent/findings")
        assert resp.status_code == 404

    def test_findings_pagination(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.get(f"/api/scans/{scan_id}/findings?page=1&per_page=1")
        data = resp.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 1
        assert data["pages"] == 3


# ---------------------------------------------------------------------------
# DELETE /api/scans/{id}
# ---------------------------------------------------------------------------


class TestDeleteScan:
    def test_delete_scan(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        create_resp = client.post("/api/scans", json=sample_scan)
        scan_id = create_resp.json()["id"]
        resp = client.delete(f"/api/scans/{scan_id}")
        assert resp.status_code == 204
        # Verify it's gone
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 404

    def test_delete_not_found(self, client: TestClient) -> None:
        resp = client.delete("/api/scans/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_empty(self, client: TestClient) -> None:
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["total_findings"] == 0

    def test_stats_with_data(
        self, client: TestClient, sample_scan: Dict[str, Any]
    ) -> None:
        client.post("/api/scans", json=sample_scan)
        resp = client.get("/api/stats")
        data = resp.json()
        assert data["total_scans"] == 1
        assert data["total_findings"] == 3
        assert "critical" in data["severity_distribution"]
        assert data["severity_distribution"]["critical"] == 1


# ---------------------------------------------------------------------------
# API Key authentication
# ---------------------------------------------------------------------------


class TestAPIKeyAuth:
    def test_no_key_required_when_not_set(self, db_path: str) -> None:
        os.environ.pop("VULNPREDICT_API_KEY", None)
        app = create_app(db_path=db_path)
        client = TestClient(app)
        resp = client.get("/api/scans")
        assert resp.status_code == 200

    def test_valid_key(self, db_path: str) -> None:
        os.environ["VULNPREDICT_API_KEY"] = "test-secret-key"
        try:
            # Need to reimport to pick up the env var
            from vulnpredict.dashboard import app as app_module
            app_module.API_KEY = "test-secret-key"
            app = create_app(db_path=db_path)
            client = TestClient(app)
            resp = client.get("/api/scans", headers={"X-API-Key": "test-secret-key"})
            assert resp.status_code == 200
        finally:
            os.environ.pop("VULNPREDICT_API_KEY", None)
            app_module.API_KEY = ""

    def test_invalid_key(self, db_path: str) -> None:
        os.environ["VULNPREDICT_API_KEY"] = "test-secret-key"
        try:
            from vulnpredict.dashboard import app as app_module
            app_module.API_KEY = "test-secret-key"
            app = create_app(db_path=db_path)
            client = TestClient(app)
            resp = client.get("/api/scans", headers={"X-API-Key": "wrong-key"})
            assert resp.status_code == 401
        finally:
            os.environ.pop("VULNPREDICT_API_KEY", None)
            app_module.API_KEY = ""

    def test_missing_key_when_required(self, db_path: str) -> None:
        os.environ["VULNPREDICT_API_KEY"] = "test-secret-key"
        try:
            from vulnpredict.dashboard import app as app_module
            app_module.API_KEY = "test-secret-key"
            app = create_app(db_path=db_path)
            client = TestClient(app)
            resp = client.get("/api/scans")
            assert resp.status_code == 401
        finally:
            os.environ.pop("VULNPREDICT_API_KEY", None)
            app_module.API_KEY = ""


# ---------------------------------------------------------------------------
# Database model tests
# ---------------------------------------------------------------------------


class TestDatabaseModel:
    def test_create_and_retrieve(self, db: Database) -> None:
        scan = db.create_scan(
            scan_path="/test",
            findings=[{"type": "test", "severity": "high"}],
        )
        assert scan is not None
        assert scan["total_findings"] == 1

    def test_list_scans_pagination(self, db: Database) -> None:
        for i in range(5):
            db.create_scan(scan_path=f"/test/{i}", findings=[])
        result = db.list_scans(page=2, per_page=2)
        assert result["total"] == 5
        assert len(result["scans"]) == 2

    def test_delete_cascades_findings(self, db: Database) -> None:
        scan = db.create_scan(
            scan_path="/test",
            findings=[{"type": "test", "severity": "high"}],
        )
        scan_id = scan["id"]
        assert db.get_findings(scan_id)["total"] == 1
        db.delete_scan(scan_id)
        assert db.get_scan(scan_id) is None
