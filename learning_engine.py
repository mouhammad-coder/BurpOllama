"""
learning_engine.py — Historical Learning Engine
Stores analyst verdicts, learns recurring false-positive patterns per technology
stack, and adjusts triage confidence scores for future scans.

Architecture:
  - SQLite persistence (upgradeable to PostgreSQL)
  - Per-technology FP fingerprints
  - Bayesian-style confidence adjustment
  - Verdict replay for A/B improvement measurement

Commercial equivalents: Nucleus Security ML triage, Rapid7 InsightVM risk scoring,
Synack auto-triage learning.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

DB_DIR  = os.path.expanduser("~/.burpollama")
DB_PATH = os.path.join(DB_DIR, "learning_engine.db")

DDL = """
CREATE TABLE IF NOT EXISTS analyst_verdicts (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT,
    scan_id         TEXT,
    vuln_type       TEXT,
    severity        TEXT,
    url             TEXT,
    tech_stack      TEXT,
    evidence_hash   TEXT,
    auto_verdict    TEXT,
    analyst_verdict TEXT,
    analyst_note    TEXT,
    was_fp          INTEGER DEFAULT 0,
    was_fn          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fp_patterns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_key     TEXT UNIQUE,
    vuln_type       TEXT,
    tech_stack      TEXT,
    fp_count        INTEGER DEFAULT 1,
    tp_count        INTEGER DEFAULT 0,
    last_seen       TEXT,
    confidence_adj  REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS technology_profiles (
    tech_name       TEXT,
    vuln_type       TEXT,
    avg_confidence  REAL,
    sample_count    INTEGER DEFAULT 0,
    fp_rate         REAL DEFAULT 0.0,
    PRIMARY KEY (tech_name, vuln_type)
);

CREATE INDEX IF NOT EXISTS idx_verdicts_vuln ON analyst_verdicts (vuln_type);
CREATE INDEX IF NOT EXISTS idx_verdicts_tech ON analyst_verdicts (tech_stack);
CREATE INDEX IF NOT EXISTS idx_fp_key        ON fp_patterns (pattern_key);
"""


class LearningEngine:
    """
    Records analyst verdicts and adjusts future triage confidence scores
    based on historical FP/TP patterns per technology stack.
    """

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._cache: Dict[str, float] = {}   # evidence_hash → confidence_delta
        self._ensure_db()

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(DDL)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db_path)
        c.row_factory = sqlite3.Row
        return c

    # ── Evidence fingerprinting ───────────────────────────────────────────────

    @staticmethod
    def _evidence_hash(vuln_type: str, evidence: str) -> str:
        """
        Structural hash of evidence — normalises numeric IDs and tokens
        so similar evidence patterns hash identically across targets.
        """
        # Strip dynamic values: numeric IDs, UUIDs, base64, timestamps
        normalised = re.sub(r'\b\d+\b', 'N', evidence)
        normalised = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'UUID', normalised, flags=re.IGNORECASE)
        normalised = re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', 'B64', normalised)
        normalised = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', normalised)
        key = "{}-{}".format(vuln_type.lower(), normalised[:200])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def _tech_key(tech_stack: list) -> str:
        return ",".join(sorted(t.lower() for t in (tech_stack or [])))

    @staticmethod
    def _pattern_key(vuln_type: str, tech_stack: list) -> str:
        tech = ",".join(sorted(t.lower() for t in (tech_stack or [])))
        return "{}:{}".format(vuln_type.lower()[:40], tech[:60])

    # ── Record verdict ────────────────────────────────────────────────────────

    def record_verdict(
        self,
        finding:        dict,
        analyst_verdict:str,
        analyst_note:   str = "",
        tech_stack:     list = None,
        scan_id:        str  = "",
    ):
        """
        Store an analyst verdict (PASS / KILL / FP / ESCALATE) for a finding.
        Automatically updates FP pattern table and technology profiles.
        """
        was_fp = 1 if analyst_verdict in ("KILL", "FP") else 0
        was_fn = 1 if analyst_verdict in ("ESCALATE", "FN") else 0
        ev_hash = self._evidence_hash(
            finding.get("vuln_type", ""),
            finding.get("evidence", "")
        )
        tech_key = self._tech_key(tech_stack)
        pat_key  = self._pattern_key(finding.get("vuln_type",""), tech_stack)
        rid      = "LV-{:.0f}".format(time.time() * 1000)

        try:
            with self._conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO analyst_verdicts
                      (id, timestamp, scan_id, vuln_type, severity, url,
                       tech_stack, evidence_hash, auto_verdict,
                       analyst_verdict, analyst_note, was_fp, was_fn)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    rid, datetime.utcnow().isoformat(), scan_id,
                    finding.get("vuln_type",""), finding.get("severity",""),
                    finding.get("url",""), tech_key, ev_hash,
                    finding.get("verdict",""), analyst_verdict,
                    analyst_note, was_fp, was_fn,
                ))

                # Update FP pattern table
                if was_fp:
                    conn.execute("""
                        INSERT INTO fp_patterns (pattern_key, vuln_type, tech_stack,
                          fp_count, last_seen)
                        VALUES (?,?,?,1,?)
                        ON CONFLICT(pattern_key) DO UPDATE SET
                          fp_count = fp_count + 1,
                          last_seen = excluded.last_seen
                    """, (pat_key, finding.get("vuln_type",""),
                          tech_key, datetime.utcnow().isoformat()))
                else:
                    conn.execute("""
                        INSERT INTO fp_patterns (pattern_key, vuln_type, tech_stack,
                          tp_count, last_seen)
                        VALUES (?,?,?,1,?)
                        ON CONFLICT(pattern_key) DO UPDATE SET
                          tp_count = tp_count + 1,
                          last_seen = excluded.last_seen
                    """, (pat_key, finding.get("vuln_type",""),
                          tech_key, datetime.utcnow().isoformat()))

                # Recalculate confidence adjustment for this pattern
                row = conn.execute(
                    "SELECT fp_count, tp_count FROM fp_patterns WHERE pattern_key=?",
                    (pat_key,)
                ).fetchone()
                if row:
                    total = row["fp_count"] + row["tp_count"]
                    if total >= 3:
                        fp_rate = row["fp_count"] / total
                        adj = -30.0 * fp_rate   # up to -30 confidence penalty
                        conn.execute(
                            "UPDATE fp_patterns SET confidence_adj=? WHERE pattern_key=?",
                            (round(adj, 1), pat_key)
                        )
                        self._cache[pat_key] = adj

        except sqlite3.Error as e:
            print("[Learning] DB error: {}".format(e))

    # ── Confidence adjustment ─────────────────────────────────────────────────

    def get_confidence_adjustment(
        self,
        vuln_type:   str,
        tech_stack:  list = None,
        evidence:    str  = "",
    ) -> float:
        """
        Return a confidence delta (-30 to +10) based on historical FP patterns.
        Negative values reduce confidence, positive values increase it.
        Called by triage_gate before routing to Gemini.
        """
        pat_key = self._pattern_key(vuln_type, tech_stack)

        # Check in-memory cache first
        if pat_key in self._cache:
            return self._cache[pat_key]

        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT confidence_adj FROM fp_patterns WHERE pattern_key=?",
                    (pat_key,)
                ).fetchone()
                if row:
                    adj = float(row["confidence_adj"])
                    self._cache[pat_key] = adj
                    return adj
        except sqlite3.Error:
            pass
        return 0.0

    def should_skip_triage(
        self,
        vuln_type:  str,
        tech_stack: list = None,
        min_fp_count: int = 5,
    ) -> Tuple[bool, str]:
        """
        If a vuln_type + tech_stack combination has been FP'd >= min_fp_count
        times historically, recommend auto-killing without API call.
        Returns (should_skip, reason).
        """
        pat_key = self._pattern_key(vuln_type, tech_stack)
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT fp_count, tp_count FROM fp_patterns WHERE pattern_key=?",
                    (pat_key,)
                ).fetchone()
                if row:
                    total = row["fp_count"] + row["tp_count"]
                    if total >= min_fp_count and row["fp_count"] / total >= 0.8:
                        return True, "Historical FP rate {:.0f}% ({}/{} verdicts)".format(
                            row["fp_count"] / total * 100,
                            row["fp_count"], total)
        except sqlite3.Error:
            pass
        return False, ""

    # ── Technology profiles ───────────────────────────────────────────────────

    def get_technology_risk_profile(self, tech_stack: list) -> dict:
        """
        Return vulnerability probability rankings for a given tech stack.
        Used by risk-based prioritisation to order which classes run first.
        """
        if not tech_stack:
            return {}
        tech_lower = [t.lower() for t in tech_stack]
        profile = {}

        # Static technology-to-vuln risk mappings (augmented by historical data)
        TECH_RISK = {
            "wordpress":  ["xss", "idor", "sqli", "file upload", "auth bypass"],
            "drupal":     ["rce", "sqli", "idor", "auth bypass"],
            "laravel":    ["sqli", "xss", "mass assignment", "idor"],
            "django":     ["sqli", "xss", "idor", "ssti"],
            "spring":     ["xxe", "ssrf", "idor", "mass assignment", "rce"],
            "express":    ["xss", "idor", "prototype pollution", "sqli"],
            "rails":      ["mass assignment", "sqli", "idor", "ssrf"],
            "graphql":    ["idor", "bola", "introspection", "sqli", "ssrf"],
            "php":        ["sqli", "xss", "file upload", "path traversal", "rce"],
            "asp.net":    ["sqli", "xxe", "idor", "viewstate"],
            "nginx":      ["cache poisoning", "http desync", "path traversal"],
            "react":      ["xss", "prototype pollution", "cors", "idor"],
            "angular":    ["xss", "cors", "idor"],
            "vue":        ["xss", "cors", "prototype pollution"],
            "jwt":        ["jwt alg:none", "auth bypass", "idor"],
            "oauth":      ["open redirect", "auth bypass", "idor", "csrf"],
            "graphiql":   ["introspection", "sqli", "idor"],
            "s3":         ["idor", "ssrf", "file upload"],
            "kubernetes": ["ssrf", "idor", "auth bypass", "rce"],
        }

        for tech in tech_lower:
            for key, vulns in TECH_RISK.items():
                if key in tech:
                    for i, v in enumerate(vulns):
                        priority = len(vulns) - i
                        profile[v] = max(profile.get(v, 0), priority)

        # Adjust by historical data
        try:
            with self._conn() as conn:
                tech_key = self._tech_key(tech_stack)
                rows = conn.execute("""
                    SELECT vuln_type, AVG(CASE WHEN was_fp=0 THEN 1 ELSE 0 END) as tp_rate,
                           COUNT(*) as count
                    FROM analyst_verdicts
                    WHERE tech_stack=?
                    GROUP BY vuln_type
                    HAVING count >= 3
                """, (tech_key,)).fetchall()
                for row in rows:
                    tp_adj = float(row["tp_rate"]) * 5
                    vt = row["vuln_type"].lower()
                    profile[vt] = profile.get(vt, 0) + tp_adj
        except sqlite3.Error:
            pass

        return dict(sorted(profile.items(), key=lambda x: x[1], reverse=True))

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        try:
            with self._conn() as conn:
                total   = conn.execute("SELECT COUNT(*) FROM analyst_verdicts").fetchone()[0]
                fp_count = conn.execute(
                    "SELECT COUNT(*) FROM analyst_verdicts WHERE was_fp=1").fetchone()[0]
                patterns = conn.execute("SELECT COUNT(*) FROM fp_patterns").fetchone()[0]
            return {
                "total_verdicts":  total,
                "false_positives": fp_count,
                "fp_rate":         round(fp_count / total * 100, 1) if total else 0,
                "fp_patterns":     patterns,
            }
        except sqlite3.Error:
            return {}


# ── Module-level singleton ────────────────────────────────────────────────────
learning_engine = LearningEngine()
