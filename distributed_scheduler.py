"""
distributed_scheduler.py - durable scan/task scheduler with retries/checkpoints.

This module is intentionally storage-light: SQLite works for a laptop or single
VM, while the schema maps cleanly to PostgreSQL SKIP LOCKED for true multi-node
workers. The public API is task-oriented so the scanner can be split across
worker processes without rewriting the pipeline.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


DB_DIR = os.path.expanduser("~/.burpollama")
DB_PATH = os.path.join(DB_DIR, "scheduler.db")

DDL = """
CREATE TABLE IF NOT EXISTS scan_tasks (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT,
    task_type       TEXT,
    payload_json    TEXT,
    status          TEXT DEFAULT 'QUEUED',
    priority        INTEGER DEFAULT 100,
    attempts        INTEGER DEFAULT 0,
    max_attempts    INTEGER DEFAULT 3,
    worker_id       TEXT,
    not_before      REAL DEFAULT 0,
    checkpoint_json TEXT DEFAULT '{}',
    last_error      TEXT,
    created_at      TEXT,
    updated_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_claim
ON scan_tasks(status, not_before, priority, created_at);

CREATE TABLE IF NOT EXISTS scan_events (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT,
    event_type   TEXT,
    payload_json TEXT,
    created_at   TEXT
);
"""


@dataclass
class ScheduledTask:
    id: str
    scan_id: str
    task_type: str
    payload: dict
    priority: int
    attempts: int
    max_attempts: int
    checkpoint: dict


class DistributedScanScheduler:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.worker_id = "{}-{}".format(os.getenv("COMPUTERNAME", "worker"), uuid.uuid4().hex[:6])
        self._ensure_db()

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DDL)

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def enqueue(self, scan_id: str, task_type: str, payload: dict,
                priority: int = 100, max_attempts: int = 3) -> str:
        task_id = "TASK-" + uuid.uuid4().hex[:16]
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO scan_tasks
                  (id, scan_id, task_type, payload_json, priority, max_attempts,
                   created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (task_id, scan_id, task_type, json.dumps(payload), priority,
                  max_attempts, now, now))
        self.emit_event(scan_id, "task.enqueued", {"task_id": task_id, "task_type": task_type})
        return task_id

    def claim_next(self) -> Optional[ScheduledTask]:
        now_epoch = time.time()
        now_iso = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("""
                SELECT * FROM scan_tasks
                WHERE status='QUEUED' AND not_before <= ?
                ORDER BY priority ASC, created_at ASC
                LIMIT 1
            """, (now_epoch,)).fetchone()
            if not row:
                conn.commit()
                return None
            conn.execute("""
                UPDATE scan_tasks
                SET status='RUNNING', worker_id=?, attempts=attempts+1, updated_at=?
                WHERE id=? AND status='QUEUED'
            """, (self.worker_id, now_iso, row["id"]))
            conn.commit()
        return ScheduledTask(
            id=row["id"],
            scan_id=row["scan_id"],
            task_type=row["task_type"],
            payload=json.loads(row["payload_json"] or "{}"),
            priority=int(row["priority"]),
            attempts=int(row["attempts"]) + 1,
            max_attempts=int(row["max_attempts"]),
            checkpoint=json.loads(row["checkpoint_json"] or "{}"),
        )

    def checkpoint(self, task_id: str, checkpoint: dict):
        with self._conn() as conn:
            conn.execute("""
                UPDATE scan_tasks SET checkpoint_json=?, updated_at=? WHERE id=?
            """, (json.dumps(checkpoint), datetime.utcnow().isoformat(), task_id))

    def complete(self, task_id: str):
        with self._conn() as conn:
            row = conn.execute("SELECT scan_id FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
            conn.execute("""
                UPDATE scan_tasks SET status='COMPLETE', updated_at=? WHERE id=?
            """, (datetime.utcnow().isoformat(), task_id))
        if row:
            self.emit_event(row["scan_id"], "task.complete", {"task_id": task_id})

    def fail(self, task_id: str, error: str, retry_delay_secs: int = 60):
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT scan_id, attempts, max_attempts FROM scan_tasks WHERE id=?",
                (task_id,),
            ).fetchone()
            if not row:
                return
            exhausted = int(row["attempts"]) >= int(row["max_attempts"])
            status = "FAILED" if exhausted else "QUEUED"
            delay = 0 if exhausted else time.time() + retry_delay_secs * max(1, int(row["attempts"]))
            conn.execute("""
                UPDATE scan_tasks
                SET status=?, not_before=?, last_error=?, worker_id=NULL, updated_at=?
                WHERE id=?
            """, (status, delay, error[:1000], now, task_id))
        self.emit_event(row["scan_id"], "task.failed" if exhausted else "task.retry",
                        {"task_id": task_id, "error": error[:300]})

    def emit_event(self, scan_id: str, event_type: str, payload: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO scan_events (id, scan_id, event_type, payload_json, created_at)
                VALUES (?,?,?,?,?)
            """, ("EV-" + uuid.uuid4().hex[:16], scan_id, event_type,
                  json.dumps(payload), datetime.utcnow().isoformat()))

    def status(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT status, COUNT(*) as c FROM scan_tasks GROUP BY status
            """).fetchall()
            queued = conn.execute("""
                SELECT task_type, COUNT(*) as c FROM scan_tasks
                WHERE status IN ('QUEUED','RUNNING') GROUP BY task_type
            """).fetchall()
        return {
            "worker_id": self.worker_id,
            "tasks_by_status": {r["status"]: r["c"] for r in rows},
            "active_by_type": {r["task_type"]: r["c"] for r in queued},
        }


scheduler = DistributedScanScheduler()
