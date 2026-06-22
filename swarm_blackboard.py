"""Durable stigmergic blackboard for BurpOllama scan agents.

The existing pipeline remains the execution safety boundary. This blackboard
adds decentralized coordination signals: agents publish observations with a
decaying pheromone weight, and other agents can query trigger predicates
without requiring a central planner to prescribe every next action.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import tempfile
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path(os.path.expanduser("~/.burpollama/swarm_blackboard.db"))

DEFAULT_HALF_LIVES = {
    "TARGET_REGISTERED": 86400,
    "SUBDOMAIN": 43200,
    "HTTP_ENDPOINT": 21600,
    "TECHNOLOGY": 43200,
    "RAW_FINDING": 7200,
    "VALIDATED_FINDING": 21600,
    "EXPLOIT_CHAIN": 43200,
    "CAMPAIGN_COMPLETE": 86400,
    "AGENT_ERROR": 1800,
}

DDL = """
CREATE TABLE IF NOT EXISTS swarm_findings (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    finding_type    TEXT NOT NULL,
    target          TEXT NOT NULL,
    data_json       TEXT NOT NULL,
    pheromone_base  REAL NOT NULL,
    half_life_sec   REAL NOT NULL,
    created_epoch   REAL NOT NULL,
    created_at      TEXT NOT NULL,
    superseded_by   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_swarm_campaign_type
ON swarm_findings(campaign_id, finding_type, created_epoch);

CREATE TABLE IF NOT EXISTS swarm_cursors (
    campaign_id  TEXT NOT NULL,
    agent_name   TEXT NOT NULL,
    cursor_epoch REAL NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY(campaign_id, agent_name)
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TriggerPredicate:
    finding_types: tuple[str, ...] = ()
    minimum_pheromone: float = 0.0
    since_epoch: float = 0.0
    target_contains: str = ""
    limit: int = 100


AGENT_TRIGGERS = {
    "classifier": TriggerPredicate(
        finding_types=("RAW_FINDING",),
        minimum_pheromone=0.2,
        limit=100,
    ),
    "validator": TriggerPredicate(
        finding_types=("RAW_FINDING",),
        minimum_pheromone=0.45,
        limit=100,
    ),
    "chain-builder": TriggerPredicate(
        finding_types=("VALIDATED_FINDING",),
        minimum_pheromone=0.65,
        limit=100,
    ),
    "report-writer": TriggerPredicate(
        finding_types=("CAMPAIGN_COMPLETE",),
        minimum_pheromone=0.1,
        limit=10,
    ),
}


class SwarmBlackboard:
    def __init__(self, path: str | Path = DEFAULT_PATH):
        self.path = Path(path)
        self._ensure_db()

    def _ensure_db(self) -> None:
        try:
            self._initialize(self.path)
        except (OSError, sqlite3.OperationalError):
            self.path = Path(tempfile.gettempdir()) / "burpollama" / "swarm_blackboard.db"
            self._initialize(self.path)

    def _initialize(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(DDL)
            connection.commit()

    @contextmanager
    def _conn(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def pheromone_at(base: float, half_life_sec: float, age_sec: float) -> float:
        if base <= 0:
            return 0.0
        if half_life_sec <= 0:
            return float(base)
        return float(base) * math.pow(0.5, max(0.0, age_sec) / half_life_sec)

    def write(
        self,
        campaign_id: str,
        agent_name: str,
        finding_type: str,
        target: str,
        data: dict[str, Any] | None = None,
        *,
        pheromone_base: float = 0.5,
        half_life_sec: float | None = None,
        created_epoch: float | None = None,
    ) -> str:
        finding_type = str(finding_type or "OBSERVATION").upper()
        epoch = float(created_epoch if created_epoch is not None else datetime.now().timestamp())
        item_id = "SW-" + uuid.uuid4().hex[:20]
        half_life = float(
            half_life_sec
            if half_life_sec is not None
            else DEFAULT_HALF_LIVES.get(finding_type, 7200)
        )
        with self._conn() as connection:
            connection.execute(
                """
                INSERT INTO swarm_findings
                  (id, campaign_id, agent_name, finding_type, target,
                   data_json, pheromone_base, half_life_sec, created_epoch,
                   created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    str(campaign_id),
                    str(agent_name),
                    finding_type,
                    str(target or ""),
                    json.dumps(data or {}, ensure_ascii=False),
                    max(0.0, float(pheromone_base)),
                    max(0.0, half_life),
                    epoch,
                    _now_iso(),
                ),
            )
        return item_id

    def query(
        self,
        campaign_id: str,
        predicate: TriggerPredicate | None = None,
        *,
        now_epoch: float | None = None,
    ) -> list[dict[str, Any]]:
        predicate = predicate or TriggerPredicate()
        now = float(now_epoch if now_epoch is not None else datetime.now().timestamp())
        clauses = ["campaign_id=?", "superseded_by=''"]
        params: list[Any] = [str(campaign_id)]
        if predicate.finding_types:
            placeholders = ",".join("?" for _ in predicate.finding_types)
            clauses.append("finding_type IN ({})".format(placeholders))
            params.extend(str(item).upper() for item in predicate.finding_types)
        if predicate.since_epoch:
            clauses.append("created_epoch>=?")
            params.append(float(predicate.since_epoch))
        if predicate.target_contains:
            clauses.append("LOWER(target) LIKE ?")
            params.append("%{}%".format(predicate.target_contains.lower()))
        params.append(max(1, min(1000, int(predicate.limit))))
        with self._conn() as connection:
            rows = connection.execute(
                """
                SELECT * FROM swarm_findings
                WHERE {}
                ORDER BY created_epoch DESC
                LIMIT ?
                """.format(" AND ".join(clauses)),
                params,
            ).fetchall()
        results = []
        for row in rows:
            pheromone = self.pheromone_at(
                float(row["pheromone_base"]),
                float(row["half_life_sec"]),
                now - float(row["created_epoch"]),
            )
            if pheromone < float(predicate.minimum_pheromone):
                continue
            results.append({
                "id": row["id"],
                "campaign_id": row["campaign_id"],
                "agent_name": row["agent_name"],
                "finding_type": row["finding_type"],
                "target": row["target"],
                "data": json.loads(row["data_json"] or "{}"),
                "pheromone": round(pheromone, 6),
                "pheromone_base": float(row["pheromone_base"]),
                "half_life_sec": float(row["half_life_sec"]),
                "created_epoch": float(row["created_epoch"]),
                "created_at": row["created_at"],
            })
        results.sort(key=lambda item: (-item["pheromone"], -item["created_epoch"]))
        return results

    def triggered(
        self,
        campaign_id: str,
        agent_name: str,
        predicate: TriggerPredicate,
    ) -> list[dict[str, Any]]:
        with self._conn() as connection:
            row = connection.execute(
                """
                SELECT cursor_epoch FROM swarm_cursors
                WHERE campaign_id=? AND agent_name=?
                """,
                (campaign_id, agent_name),
            ).fetchone()
        cursor = float(row["cursor_epoch"]) if row else 0.0
        effective = TriggerPredicate(
            finding_types=predicate.finding_types,
            minimum_pheromone=predicate.minimum_pheromone,
            since_epoch=max(cursor, predicate.since_epoch),
            target_contains=predicate.target_contains,
            limit=predicate.limit,
        )
        return self.query(campaign_id, effective)

    def commit_cursor(
        self,
        campaign_id: str,
        agent_name: str,
        cursor_epoch: float,
    ) -> None:
        with self._conn() as connection:
            connection.execute(
                """
                INSERT INTO swarm_cursors
                  (campaign_id, agent_name, cursor_epoch, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(campaign_id, agent_name) DO UPDATE SET
                  cursor_epoch=MAX(cursor_epoch, excluded.cursor_epoch),
                  updated_at=excluded.updated_at
                """,
                (campaign_id, agent_name, float(cursor_epoch), _now_iso()),
            )

    def supersede(self, finding_id: str, replacement_id: str) -> bool:
        with self._conn() as connection:
            cursor = connection.execute(
                """
                UPDATE swarm_findings SET superseded_by=?
                WHERE id=? AND superseded_by=''
                """,
                (replacement_id, finding_id),
            )
        return bool(cursor.rowcount)

    def status(self, campaign_id: str) -> dict[str, Any]:
        items = self.query(campaign_id, TriggerPredicate(limit=1000))
        by_type: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        for item in items:
            by_type[item["finding_type"]] = by_type.get(item["finding_type"], 0) + 1
            by_agent[item["agent_name"]] = by_agent.get(item["agent_name"], 0) + 1
        return {
            "campaign_id": campaign_id,
            "total_items": len(items),
            "items_by_type": by_type,
            "items_by_agent": by_agent,
            "hot_items": items[:25],
            "db_path": str(self.path),
        }

    def ready_agents(self, campaign_id: str) -> list[dict[str, Any]]:
        ready = []
        for agent_name, predicate in AGENT_TRIGGERS.items():
            items = self.triggered(campaign_id, agent_name, predicate)
            if not items:
                continue
            ready.append({
                "agent_name": agent_name,
                "trigger_count": len(items),
                "highest_pheromone": max(
                    item["pheromone"] for item in items
                ),
                "trigger_types": list(predicate.finding_types),
            })
        ready.sort(
            key=lambda item: (
                -item["highest_pheromone"],
                -item["trigger_count"],
                item["agent_name"],
            )
        )
        return ready


swarm_blackboard = SwarmBlackboard()
