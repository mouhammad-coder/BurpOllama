"""
storage.py - database evolution path: PostgreSQL-ready event store and audit log.

Set BURPOLLAMA_DATABASE_URL=postgresql://... to make deployment intent explicit.
The current implementation uses SQLite-compatible SQL so local installs keep
working; the interface is the stable migration boundary for PostgreSQL pooling.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime

try:
    from psycopg_pool import ConnectionPool  # type: ignore
except Exception:  # pragma: no cover - optional deployment dependency
    ConnectionPool = None


DB_DIR = os.path.expanduser("~/.burpollama")
DB_PATH = os.path.join(DB_DIR, "events.db")
DATABASE_URL = os.getenv("BURPOLLAMA_DATABASE_URL", "sqlite:///{}".format(DB_PATH))

DDL = """
CREATE TABLE IF NOT EXISTS event_log (
    id           TEXT PRIMARY KEY,
    stream_id    TEXT,
    event_type   TEXT,
    actor        TEXT,
    payload_json TEXT,
    created_at   TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           TEXT PRIMARY KEY,
    actor        TEXT,
    action       TEXT,
    target       TEXT,
    payload_json TEXT,
    created_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_event_stream ON event_log(stream_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target, created_at);
"""


class EventStore:
    def __init__(self, database_url: str = DATABASE_URL):
        self.database_url = database_url
        self.postgres_configured = database_url.startswith("postgres")
        self.pool = None
        self.db_path = DB_PATH
        if database_url.startswith("sqlite:///"):
            self.db_path = database_url.replace("sqlite:///", "", 1)
        if self.postgres_configured and ConnectionPool:
            self.pool = ConnectionPool(conninfo=database_url, min_size=1, max_size=10, open=True)
        self._ensure_db()

    def _ensure_db(self):
        if self.pool:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(DDL)
                conn.commit()
            return
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DDL)

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def append(self, stream_id: str, event_type: str, payload: dict, actor: str = "system") -> str:
        eid = "EV-" + uuid.uuid4().hex[:16]
        if self.pool:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO event_log (id, stream_id, event_type, actor, payload_json, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s)
                    """, (eid, stream_id, event_type, actor, json.dumps(payload),
                          datetime.utcnow().isoformat()))
                conn.commit()
            return eid
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO event_log (id, stream_id, event_type, actor, payload_json, created_at)
                VALUES (?,?,?,?,?,?)
            """, (eid, stream_id, event_type, actor, json.dumps(payload),
                  datetime.utcnow().isoformat()))
        return eid

    def audit(self, actor: str, action: str, target: str, payload: dict | None = None) -> str:
        aid = "AUD-" + uuid.uuid4().hex[:16]
        if self.pool:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO audit_log (id, actor, action, target, payload_json, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s)
                    """, (aid, actor, action, target, json.dumps(payload or {}),
                          datetime.utcnow().isoformat()))
                conn.commit()
            return aid
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO audit_log (id, actor, action, target, payload_json, created_at)
                VALUES (?,?,?,?,?,?)
            """, (aid, actor, action, target, json.dumps(payload or {}),
                  datetime.utcnow().isoformat()))
        return aid

    def stream(self, stream_id: str, limit: int = 200) -> list[dict]:
        if self.pool:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, stream_id, event_type, actor, payload_json, created_at
                        FROM event_log WHERE stream_id=%s ORDER BY created_at DESC LIMIT %s
                    """, (stream_id, limit))
                    cols = [d.name for d in cur.description]
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM event_log WHERE stream_id=? ORDER BY created_at DESC LIMIT ?
            """, (stream_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def status(self) -> dict:
        if self.pool:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM event_log")
                    events = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM audit_log")
                    audits = cur.fetchone()[0]
            return {
                "database_url": "postgresql://...",
                "postgres_configured": True,
                "pool_enabled": True,
                "events": events,
                "audit_events": audits,
                "retention_policy": os.getenv("BURPOLLAMA_RETENTION_DAYS", "90") + " days",
            }
        with self._conn() as conn:
            events = conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
            audits = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {
            "database_url": "postgresql://..." if self.postgres_configured else "sqlite",
            "postgres_configured": self.postgres_configured,
            "pool_enabled": bool(self.pool),
            "events": events,
            "audit_events": audits,
            "retention_policy": os.getenv("BURPOLLAMA_RETENTION_DAYS", "90") + " days",
        }


event_store = EventStore()
