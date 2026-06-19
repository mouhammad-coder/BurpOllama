"""
autopilot_state.py - durable local Autopilot run/task/event/output state.

This is intentionally local-server first: SQLite gives Kali/laptop durability
without introducing an external service, while the tables map directly to a
future PostgreSQL migration.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any


DB_DIR = os.path.expanduser("~/.burpollama")
DB_PATH = os.path.join(DB_DIR, "autopilot.db")

DDL = """
CREATE TABLE IF NOT EXISTS autopilot_runs (
    scan_id       TEXT PRIMARY KEY,
    target        TEXT,
    status        TEXT,
    phase         TEXT,
    resume_token  TEXT,
    checkpoint_json TEXT DEFAULT '{}',
    created_at    TEXT,
    updated_at    TEXT,
    finished_at   TEXT
);

CREATE TABLE IF NOT EXISTS autopilot_tasks (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT,
    task_type     TEXT,
    status        TEXT,
    attempts      INTEGER DEFAULT 0,
    checkpoint_json TEXT DEFAULT '{}',
    last_error    TEXT,
    created_at    TEXT,
    updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS autopilot_events (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT,
    event_type    TEXT,
    payload_json  TEXT,
    created_at    TEXT
);

CREATE TABLE IF NOT EXISTS autopilot_agent_outputs (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT,
    agent         TEXT,
    output_type   TEXT,
    payload_json  TEXT,
    created_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_autopilot_events_scan_time
ON autopilot_events(scan_id, created_at);

CREATE INDEX IF NOT EXISTS idx_autopilot_tasks_scan_status
ON autopilot_tasks(scan_id, status);
"""


class AutopilotStateStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DDL)

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def status(self) -> dict[str, Any]:
        with self._conn() as conn:
            tables = {}
            for table in ("autopilot_runs", "autopilot_tasks", "autopilot_events", "autopilot_agent_outputs"):
                row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
                tables[table] = int(row["c"])
        return {"db_path": self.db_path, "tables": tables}

    def create_run(self, scan_id: str, target: str, status: str = "queued", phase: str = "queued") -> str:
        token = "RESUME-" + uuid.uuid4().hex[:20]
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO autopilot_runs
                  (scan_id, target, status, phase, resume_token, checkpoint_json, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (scan_id, target, status, phase, token, "{}", now, now))
        self.event(scan_id, "run.created", {"target": target, "status": status, "phase": phase})
        return token

    def update_run(self, scan_id: str, status: str | None = None, phase: str | None = None,
                   checkpoint: dict | None = None, finished: bool = False):
        now = datetime.utcnow().isoformat()
        existing = self.get_run(scan_id)
        merged_checkpoint = dict(existing.get("checkpoint", {}) if existing else {})
        if checkpoint:
            merged_checkpoint.update(checkpoint)
        with self._conn() as conn:
            conn.execute("""
                UPDATE autopilot_runs
                SET status=COALESCE(?, status),
                    phase=COALESCE(?, phase),
                    checkpoint_json=?,
                    updated_at=?,
                    finished_at=CASE WHEN ? THEN ? ELSE finished_at END
                WHERE scan_id=?
            """, (status, phase, json.dumps(merged_checkpoint), now, bool(finished), now, scan_id))
        self.event(scan_id, "run.updated", {"status": status, "phase": phase, "checkpoint": checkpoint or {}})

    def get_run(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM autopilot_runs WHERE scan_id=?", (scan_id,)).fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "status": row["status"],
            "phase": row["phase"],
            "resume_token": row["resume_token"],
            "checkpoint": json.loads(row["checkpoint_json"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "finished_at": row["finished_at"],
        }

    def upsert_task(self, scan_id: str, task_type: str, status: str,
                    checkpoint: dict | None = None, error: str = "") -> str:
        now = datetime.utcnow().isoformat()
        task_id = f"{scan_id}:{task_type}"
        with self._conn() as conn:
            row = conn.execute("SELECT attempts FROM autopilot_tasks WHERE id=?", (task_id,)).fetchone()
            attempts = int(row["attempts"]) + (1 if status in ("running", "retrying") else 0) if row else 0
            conn.execute("""
                INSERT INTO autopilot_tasks
                  (id, scan_id, task_type, status, attempts, checkpoint_json, last_error, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  status=excluded.status,
                  attempts=excluded.attempts,
                  checkpoint_json=excluded.checkpoint_json,
                  last_error=excluded.last_error,
                  updated_at=excluded.updated_at
            """, (task_id, scan_id, task_type, status, attempts, json.dumps(checkpoint or {}),
                  error[:1000], now, now))
        self.event(scan_id, "task.updated", {"task_id": task_id, "task_type": task_type, "status": status})
        return task_id

    def event(self, scan_id: str, event_type: str, payload: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO autopilot_events (id, scan_id, event_type, payload_json, created_at)
                VALUES (?,?,?,?,?)
            """, ("EV-" + uuid.uuid4().hex[:16], scan_id, event_type,
                  json.dumps(payload or {}), datetime.utcnow().isoformat()))

    def output(self, scan_id: str, agent: str, output_type: str, payload: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO autopilot_agent_outputs (id, scan_id, agent, output_type, payload_json, created_at)
                VALUES (?,?,?,?,?,?)
            """, ("OUT-" + uuid.uuid4().hex[:16], scan_id, agent, output_type,
                  json.dumps(payload or {}), datetime.utcnow().isoformat()))

    def recent_events(self, scan_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM autopilot_events WHERE scan_id=?
                ORDER BY created_at DESC LIMIT ?
            """, (scan_id, limit)).fetchall()
        return [
            {"id": r["id"], "event_type": r["event_type"],
             "payload": json.loads(r["payload_json"] or "{}"), "created_at": r["created_at"]}
            for r in rows
        ]

    def tasks(self, scan_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM autopilot_tasks WHERE scan_id=? ORDER BY created_at ASC
            """, (scan_id,)).fetchall()
        return [
            {"id": r["id"], "task_type": r["task_type"], "status": r["status"],
             "attempts": r["attempts"], "checkpoint": json.loads(r["checkpoint_json"] or "{}"),
             "last_error": r["last_error"], "updated_at": r["updated_at"]}
            for r in rows
        ]

    def agent_outputs(self, scan_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM autopilot_agent_outputs WHERE scan_id=?
                ORDER BY created_at DESC LIMIT ?
            """, (scan_id, limit)).fetchall()
        return [
            {"id": r["id"], "agent": r["agent"], "output_type": r["output_type"],
             "payload": json.loads(r["payload_json"] or "{}"), "created_at": r["created_at"]}
            for r in rows
        ]


autopilot_state = AutopilotStateStore()
