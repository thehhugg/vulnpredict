"""FastAPI application for the VulnPredict dashboard API."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from .models import Database

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_KEY = os.environ.get("VULNPREDICT_API_KEY", "")
DB_PATH = os.environ.get("VULNPREDICT_DB_PATH", "vulnpredict_dashboard.db")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """A single finding in a scan submission."""

    type: str = "unknown"
    severity: str = "low"
    file: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    rule_id: Optional[str] = None
    cwe: Optional[str] = None


class ScanInput(BaseModel):
    """Request body for submitting a new scan."""

    scan_path: str
    findings: List[FindingInput]
    files_scanned: Optional[int] = None
    scan_duration: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    """Response for a single scan."""

    id: str
    scan_path: str
    status: str
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    critical_count: int
    files_scanned: Optional[int] = None
    scan_duration: Optional[float] = None
    created_at: str


class PaginatedScans(BaseModel):
    """Paginated list of scans."""

    scans: List[Dict[str, Any]]
    total: int
    page: int
    per_page: int
    pages: int


class PaginatedFindings(BaseModel):
    """Paginated list of findings."""

    findings: List[Dict[str, Any]]
    total: int
    page: int
    per_page: int
    pages: int


class StatsResponse(BaseModel):
    """Aggregate statistics."""

    total_scans: int
    total_findings: int
    severity_distribution: Dict[str, int]
    type_distribution: Dict[str, int]
    recent_scans: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _get_db() -> Database:
    """Dependency that provides a Database instance."""
    return Database(db_path=DB_PATH)


def _check_api_key(api_key: Optional[str] = Security(_api_key_header)) -> None:
    """Validate API key if one is configured."""
    if API_KEY and api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def create_app(db_path: Optional[str] = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        db_path: Optional override for the database path.

    Returns:
        Configured FastAPI application.
    """
    global DB_PATH
    if db_path:
        DB_PATH = db_path

    app = FastAPI(
        title="VulnPredict Dashboard API",
        description="REST API for storing and querying VulnPredict scan results",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Health check ---

    @app.get("/api/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    # --- Scans ---

    @app.post("/api/scans", status_code=201, dependencies=[Depends(_check_api_key)])
    def create_scan(
        body: ScanInput,
        db: Database = Depends(_get_db),
    ) -> Dict[str, Any]:
        findings_dicts = [f.model_dump() for f in body.findings]
        scan = db.create_scan(
            scan_path=body.scan_path,
            findings=findings_dicts,
            files_scanned=body.files_scanned,
            scan_duration=body.scan_duration,
            metadata=body.metadata,
        )
        return scan

    @app.get("/api/scans", dependencies=[Depends(_check_api_key)])
    def list_scans(
        page: int = Query(1, ge=1),
        per_page: int = Query(20, ge=1, le=100),
        db: Database = Depends(_get_db),
    ) -> Dict[str, Any]:
        return db.list_scans(page=page, per_page=per_page)

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(_check_api_key)])
    def get_scan(
        scan_id: str,
        db: Database = Depends(_get_db),
    ) -> Dict[str, Any]:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    @app.get("/api/scans/{scan_id}/findings", dependencies=[Depends(_check_api_key)])
    def get_findings(
        scan_id: str,
        severity: Optional[str] = None,
        type: Optional[str] = None,
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=200),
        db: Database = Depends(_get_db),
    ) -> Dict[str, Any]:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return db.get_findings(
            scan_id=scan_id,
            severity=severity,
            finding_type=type,
            page=page,
            per_page=per_page,
        )

    @app.delete(
        "/api/scans/{scan_id}",
        status_code=204,
        dependencies=[Depends(_check_api_key)],
    )
    def delete_scan(
        scan_id: str,
        db: Database = Depends(_get_db),
    ) -> None:
        if not db.delete_scan(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")

    # --- Stats ---

    @app.get("/api/stats", dependencies=[Depends(_check_api_key)])
    def get_stats(
        db: Database = Depends(_get_db),
    ) -> Dict[str, Any]:
        return db.get_stats()

    return app


# Default app instance for `uvicorn vulnpredict.dashboard.app:app`
app = create_app()
