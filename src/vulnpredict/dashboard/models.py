"""SQLite database models for the VulnPredict dashboard."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Simple SQLite-backed storage for scan results."""

    def __init__(self, db_path: str = "vulnpredict_dashboard.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed',
                total_findings INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                critical_count INTEGER NOT NULL DEFAULT 0,
                files_scanned INTEGER,
                scan_duration REAL,
                metadata TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                file TEXT,
                line INTEGER,
                message TEXT,
                rule_id TEXT,
                cwe TEXT,
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
        """)
        conn.commit()
        conn.close()

    # ----- Scans -----

    def create_scan(
        self,
        scan_path: str,
        findings: List[Dict[str, Any]],
        files_scanned: Optional[int] = None,
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store a new scan and its findings."""
        scan_id = str(uuid.uuid4())
        now = _now_utc()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO scans
               (id, scan_path, total_findings, high_count, medium_count,
                low_count, critical_count, files_scanned, scan_duration,
                metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                scan_path,
                len(findings),
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
                severity_counts["critical"],
                files_scanned,
                scan_duration,
                json.dumps(metadata) if metadata else None,
                now,
            ),
        )

        for i, finding in enumerate(findings):
            conn.execute(
                """INSERT INTO findings
                   (scan_id, finding_id, type, severity, file, line,
                    message, rule_id, cwe, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding.get("id", f"VP-{i + 1:04d}"),
                    finding.get("type", "unknown"),
                    finding.get("severity", "low"),
                    finding.get("file"),
                    finding.get("line"),
                    finding.get("message"),
                    finding.get("rule_id"),
                    finding.get("cwe"),
                    json.dumps(finding),
                ),
            )

        conn.commit()
        conn.close()

        return self.get_scan(scan_id)  # type: ignore[return-value]

    def list_scans(
        self,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        """List scans with pagination."""
        conn = self._get_conn()
        offset = (page - 1) * per_page

        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (per_page, offset),
        ).fetchall()
        conn.close()

        return {
            "scans": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page if per_page > 0 else 0,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single scan by ID."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        if row is None:
            return None
        return dict(row)

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Dict[str, Any]:
        """Get findings for a scan with optional filtering."""
        conn = self._get_conn()
        offset = (page - 1) * per_page

        conditions = ["scan_id = ?"]
        params: List[Any] = [scan_id]

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if finding_type:
            conditions.append("type = ?")
            params.append(finding_type)

        where = " AND ".join(conditions)

        total = conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
        conn.close()

        return {
            "findings": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page if per_page > 0 else 0,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics across all scans."""
        conn = self._get_conn()

        scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

        severity_dist = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall():
            severity_dist[row["severity"]] = row["cnt"]

        type_dist = {}
        for row in conn.execute(
            "SELECT type, COUNT(*) as cnt FROM findings GROUP BY type ORDER BY cnt DESC LIMIT 10"
        ).fetchall():
            type_dist[row["type"]] = row["cnt"]

        recent = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

        conn.close()

        return {
            "total_scans": scan_count,
            "total_findings": finding_count,
            "severity_distribution": severity_dist,
            "type_distribution": type_dist,
            "recent_scans": [dict(r) for r in recent],
        }

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings."""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()
        return deleted
