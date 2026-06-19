"""
review_queue.py — SQLite-backed AMBIGUOUS_PARSE Review Queue
Instead of silently KILL-defaulting on Gemini JSON parse failures,
routes findings to a persistent queue for human manual inspection.
Prevents false negatives from transient API formatting errors.
"""

import sqlite3
import json
import os
import time
from datetime import datetime
from typing import Optional

DB_DIR  = os.path.expanduser("~/.burpollama")
DB_PATH = os.path.join(DB_DIR, "review_queue.db")

# ── Schema ────────────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS ambiguous_findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT,
    timestamp       TEXT,
    vuln_type       TEXT,
    severity        TEXT,
    url             TEXT,
    method          TEXT,
    description     TEXT,
    evidence        TEXT,
    raw_gemini_out  TEXT,
    fail_reason     TEXT,
    status          TEXT DEFAULT 'PENDING',  -- PENDING | REVIEWED | ESCALATED | DISMISSED
    verdict         TEXT,
    reviewer_note   TEXT,
    reviewed_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan  ON ambiguous_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_status ON ambiguous_findings (status);
"""


class ReviewQueue:
    """
    Persistent SQLite queue for findings that failed AI triage JSON parsing.

    Lifecycle:
        triage_gate.py  → parse failure  → review_queue.add_ambiguous()
        Dashboard /review endpoint        → list, inspect, resolve
        User marks ESCALATED              → finding re-enters main pipeline
        User marks DISMISSED              → finding archived
    """

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(DDL)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db_path)
        c.row_factory = sqlite3.Row
        return c

    # ── Write ─────────────────────────────────────────────────────────────────

    def add_ambiguous(
        self,
        finding:         dict,
        raw_gemini_out:  str  = "",
        fail_reason:     str  = "",
        scan_id:         str  = "",
    ) -> str:
        """
        Persist a finding that failed JSON triage parsing.
        Returns the stored ID.
        """
        fid = finding.get("id") or "AMB-{:.0f}".format(time.time() * 1000)
        try:
            with self._conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO ambiguous_findings
                      (id, scan_id, timestamp, vuln_type, severity, url, method,
                       description, evidence, raw_gemini_out, fail_reason, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    fid,
                    scan_id,
                    datetime.utcnow().isoformat(),
                    finding.get("vuln_type",   "Unknown"),
                    finding.get("severity",    "UNKNOWN"),
                    finding.get("url",         ""),
                    finding.get("method",      "GET"),
                    finding.get("description", ""),
                    finding.get("evidence",    "")[:1000],
                    raw_gemini_out[:4000],
                    fail_reason[:500],
                    "PENDING",
                ))
        except sqlite3.Error as e:
            print("[ReviewQueue] DB write error: {}".format(e))
        return fid

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_pending(self, scan_id: Optional[str] = None) -> list:
        """Return all PENDING findings, optionally filtered by scan."""
        try:
            with self._conn() as conn:
                if scan_id:
                    rows = conn.execute(
                        "SELECT * FROM ambiguous_findings WHERE status='PENDING' AND scan_id=?",
                        (scan_id,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM ambiguous_findings WHERE status='PENDING'"
                    ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error as e:
            print("[ReviewQueue] DB read error: {}".format(e))
            return []

    def get_all(self, scan_id: Optional[str] = None, limit: int = 200) -> list:
        """Return all findings regardless of status."""
        try:
            with self._conn() as conn:
                if scan_id:
                    rows = conn.execute(
                        "SELECT * FROM ambiguous_findings WHERE scan_id=? ORDER BY timestamp DESC LIMIT ?",
                        (scan_id, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM ambiguous_findings ORDER BY timestamp DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error as e:
            print("[ReviewQueue] DB read error: {}".format(e))
            return []

    def count_pending(self) -> int:
        try:
            with self._conn() as conn:
                return conn.execute(
                    "SELECT COUNT(*) FROM ambiguous_findings WHERE status='PENDING'"
                ).fetchone()[0]
        except sqlite3.Error:
            return 0

    # ── Resolve ───────────────────────────────────────────────────────────────

    def resolve(
        self,
        finding_id:    str,
        verdict:       str,   # PASS | KILL | ESCALATED | DISMISSED
        reviewer_note: str = "",
    ) -> bool:
        """Mark a finding as reviewed with a human verdict."""
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ambiguous_findings WHERE id=?", (finding_id,)
                ).fetchone()
                conn.execute("""
                    UPDATE ambiguous_findings
                    SET status='REVIEWED', verdict=?, reviewer_note=?, reviewed_at=?
                    WHERE id=?
                """, (verdict, reviewer_note, datetime.utcnow().isoformat(), finding_id))
            if row:
                try:
                    from learning_engine import learning_engine
                    learning_engine.record_verdict(
                        finding=dict(row),
                        analyst_verdict=verdict,
                        analyst_note=reviewer_note,
                        scan_id=row["scan_id"] or "",
                    )
                except Exception:
                    pass
            return True
        except sqlite3.Error as e:
            print("[ReviewQueue] resolve error: {}".format(e))
            return False

    def add_note(self, finding_id: str, reviewer_note: str = "") -> bool:
        try:
            with self._conn() as conn:
                conn.execute("""
                    UPDATE ambiguous_findings
                    SET reviewer_note=?, reviewed_at=?
                    WHERE id=?
                """, (reviewer_note, datetime.utcnow().isoformat(), finding_id))
            return True
        except sqlite3.Error as e:
            print("[ReviewQueue] note error: {}".format(e))
            return False

    def escalate(self, finding_id: str) -> Optional[dict]:
        """
        Escalate a PENDING finding back into the main pipeline.
        Returns the finding dict with verdict=PASS for re-injection.
        """
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ambiguous_findings WHERE id=?", (finding_id,)
                ).fetchone()
                if not row:
                    return None
                conn.execute(
                    "UPDATE ambiguous_findings SET status='ESCALATED' WHERE id=?",
                    (finding_id,)
                )
                f = dict(row)
                return {
                    "id":          f["id"],
                    "vuln_type":   f["vuln_type"],
                    "severity":    f["severity"],
                    "url":         f["url"],
                    "method":      f["method"],
                    "description": f["description"],
                    "evidence":    f["evidence"],
                    "verdict":     "PASS",
                    "triaged":     True,
                    "source":      "review-queue-escalated",
                    "triage": {
                        "verdict":        "PASS",
                        "kill_reason":    "",
                        "chain_hint":     "",
                        "impact_statement": "Manually escalated from AMBIGUOUS_PARSE review queue.",
                        "confidence_adjusted": 50,
                        "_manually_reviewed": True,
                    }
                }
        except sqlite3.Error as e:
            print("[ReviewQueue] escalate error: {}".format(e))
            return None


# ── Module-level singleton ────────────────────────────────────────────────────
review_queue = ReviewQueue()
