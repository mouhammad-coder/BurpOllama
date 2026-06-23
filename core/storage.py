"""Durable standalone scan history and report storage."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATA_DIR = Path(os.getenv("BURPOLLAMA_DATA_DIR", "~/.burpollama")).expanduser()
DB_PATH = DATA_DIR / "scans.db"


def _json_default(value: Any):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


class ScanStore:
    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.db_path), timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id       TEXT PRIMARY KEY,
                    target        TEXT NOT NULL,
                    mode          TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    phase         TEXT NOT NULL,
                    started_at    TEXT NOT NULL,
                    finished_at   TEXT,
                    findings      INTEGER NOT NULL DEFAULT 0,
                    scan_json     TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_started
                    ON scans(started_at DESC);

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id    TEXT PRIMARY KEY,
                    scan_id       TEXT NOT NULL,
                    severity      TEXT,
                    title         TEXT,
                    proof_status  TEXT,
                    finding_json  TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan
                    ON findings(scan_id, severity);

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id   TEXT PRIMARY KEY,
                    scan_id       TEXT NOT NULL,
                    finding_id    TEXT,
                    evidence_json TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_scan
                    ON evidence(scan_id, finding_id);

                CREATE TABLE IF NOT EXISTS reports (
                    scan_id       TEXT NOT NULL,
                    report_format TEXT NOT NULL,
                    report_path   TEXT NOT NULL,
                    created_at    TEXT NOT NULL,
                    PRIMARY KEY(scan_id, report_format)
                );
                """
            )

    def writable(self) -> bool:
        try:
            with self._connection() as connection:
                connection.execute("SELECT 1").fetchone()
            return True
        except (OSError, sqlite3.Error):
            return False

    def save(self, scan: dict[str, Any], findings: list[dict] | None = None) -> None:
        snapshot = dict(scan)
        if findings is not None:
            snapshot["findings"] = findings
        scan_id = str(snapshot.get("id") or snapshot.get("scan_id") or "")
        if not scan_id:
            raise ValueError("Scan record requires an id.")
        triaged = snapshot.get("triaged_findings") or snapshot.get("findings") or []
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(snapshot, default=_json_default, ensure_ascii=False)
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, target, mode, status, phase, started_at,
                    finished_at, findings, scan_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    target=excluded.target,
                    mode=excluded.mode,
                    status=excluded.status,
                    phase=excluded.phase,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    findings=excluded.findings,
                    scan_json=excluded.scan_json,
                    updated_at=excluded.updated_at
                """,
                (
                    scan_id,
                    str(snapshot.get("target", "")),
                    str(
                        snapshot.get("requested_scan_mode")
                        or snapshot.get("effective_scan_mode")
                        or "passive_only"
                    ),
                    str(snapshot.get("status", "unknown")),
                    str(snapshot.get("phase", "unknown")),
                    str(snapshot.get("started", now)),
                    str(snapshot.get("finished", "")),
                    len(triaged),
                    payload,
                    now,
                ),
            )
            if findings is not None:
                connection.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
                for index, finding in enumerate(findings):
                    finding_id = str(
                        finding.get("id") or f"{scan_id}-finding-{index + 1}"
                    )
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO findings (
                            finding_id, scan_id, severity, title, proof_status,
                            finding_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding_id,
                            scan_id,
                            str(finding.get("severity", "INFO")),
                            str(
                                finding.get("title")
                                or finding.get("vuln_type")
                                or "Finding"
                            ),
                            str(
                                finding.get("exploitability_status")
                                or finding.get("verdict")
                                or "candidate"
                            ),
                            json.dumps(
                                finding, default=_json_default, ensure_ascii=False
                            ),
                            now,
                        ),
                    )
                    evidence = finding.get("evidence")
                    if evidence:
                        evidence_id = str(
                            finding.get("raw_evidence_id")
                            or f"{finding_id}-evidence"
                        )
                        connection.execute(
                            """
                            INSERT OR REPLACE INTO evidence (
                                evidence_id, scan_id, finding_id,
                                evidence_json, created_at
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                evidence_id,
                                scan_id,
                                finding_id,
                                json.dumps(
                                    {
                                        "evidence": evidence,
                                        "redaction_status": finding.get(
                                            "redaction_status", "unknown"
                                        ),
                                    },
                                    ensure_ascii=False,
                                ),
                                now,
                            ),
                        )

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT scan_json FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
        return json.loads(row["scan_json"]) if row else None

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT scan_id, target, mode, status, phase, started_at,
                       finished_at, findings
                FROM scans ORDER BY started_at DESC LIMIT ?
                """,
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def status(self) -> dict[str, Any]:
        with self._connection() as connection:
            count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            findings = connection.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]
        return {
            "database": str(self.db_path),
            "writable": self.writable(),
            "scan_count": count,
            "finding_count": findings,
        }

    def save_report(self, scan_id: str, report_format: str, path: str | Path) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO reports (
                    scan_id, report_format, report_path, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    scan_id,
                    str(report_format),
                    str(Path(path)),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def reports(self, scan_id: str) -> dict[str, str]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT report_format, report_path
                FROM reports WHERE scan_id=? ORDER BY report_format
                """,
                (scan_id,),
            ).fetchall()
        return {row["report_format"]: row["report_path"] for row in rows}


scan_store = ScanStore()
