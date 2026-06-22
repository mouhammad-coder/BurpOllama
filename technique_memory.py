"""Persistent technique and outcome memory for future scan prioritization."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_PATH = Path(os.path.expanduser("~/.burpollama/technique_memory.db"))


class TechniqueMemory:
    def __init__(self, path: str | Path = DEFAULT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS technique_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    vuln_class TEXT NOT NULL,
                    tech_stack TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    confidence REAL NOT NULL DEFAULT 0,
                    false_positive INTEGER NOT NULL DEFAULT 0,
                    notes TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_technique_lookup
                    ON technique_outcomes(technique, vuln_class, outcome);
                """
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def record(
        self,
        technique: str,
        outcome: str,
        *,
        vuln_class: str = "",
        tech_stack: list[str] | None = None,
        findings_count: int = 0,
        confidence: float = 0.0,
        false_positive: bool = False,
        notes: str = "",
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO technique_outcomes
                (created_at, technique, vuln_class, tech_stack, outcome,
                 findings_count, confidence, false_positive, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    technique.strip(), vuln_class.strip(),
                    json.dumps(sorted(set(tech_stack or []))),
                    outcome.strip(), max(0, int(findings_count)),
                    max(0.0, min(100.0, float(confidence))),
                    int(bool(false_positive)), notes[:2000],
                ),
            )
            return int(cursor.lastrowid)

    def recent(self, limit: int = 50) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM technique_outcomes ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def recommendations(self, tech_stack: list[str] | None = None, limit: int = 10) -> list[dict]:
        wanted = {item.lower() for item in (tech_stack or [])}
        rows = self.recent(500)
        scores: dict[tuple[str, str], dict] = {}
        for row in rows:
            row_stack = {item.lower() for item in json.loads(row["tech_stack"] or "[]")}
            if wanted and row_stack and not wanted.intersection(row_stack):
                continue
            key = (row["technique"], row["vuln_class"])
            item = scores.setdefault(
                key,
                {"technique": key[0], "vuln_class": key[1], "runs": 0, "findings": 0, "false_positives": 0},
            )
            item["runs"] += 1
            item["findings"] += int(row["findings_count"])
            item["false_positives"] += int(row["false_positive"])
        for item in scores.values():
            item["score"] = round(
                (item["findings"] * 10 + item["runs"]) /
                max(1, item["runs"] + item["false_positives"] * 2),
                2,
            )
        return sorted(scores.values(), key=lambda item: item["score"], reverse=True)[:limit]

    def stats(self) -> dict:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS runs, COALESCE(SUM(findings_count), 0) AS findings,
                       COALESCE(SUM(false_positive), 0) AS false_positives
                FROM technique_outcomes
                """
            ).fetchone()
        return dict(row)
