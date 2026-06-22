"""Daily monitoring for newly observed public bug-bounty scope assets.

The monitor intentionally separates discovery from testing:

* Public scope feeds are advisory and may be stale or incomplete.
* The first successful fetch creates a baseline and never launches scans.
* A later addition is queued for review.
* Automatic scans require both a saved authorization rule and a matching
  central ScopePolicy rule.
* Active testing is never enabled by this module. The configured global scan
  mode remains the source of truth.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx


DEFAULT_FEEDS = {
    "hackerone": (
        "https://raw.githubusercontent.com/arkadiyt/"
        "bounty-targets-data/main/data/hackerone_data.json"
    ),
    "bugcrowd": (
        "https://raw.githubusercontent.com/arkadiyt/"
        "bounty-targets-data/main/data/bugcrowd_data.json"
    ),
    "intigriti": (
        "https://raw.githubusercontent.com/arkadiyt/"
        "bounty-targets-data/main/data/intigriti_data.json"
    ),
    "yeswehack": (
        "https://raw.githubusercontent.com/arkadiyt/"
        "bounty-targets-data/main/data/yeswehack_data.json"
    ),
    "federacy": (
        "https://raw.githubusercontent.com/arkadiyt/"
        "bounty-targets-data/main/data/federacy_data.json"
    ),
}

DDL = """
CREATE TABLE IF NOT EXISTS feed_state (
    platform       TEXT PRIMARY KEY,
    etag           TEXT,
    last_modified  TEXT,
    last_checked   TEXT,
    last_success   TEXT,
    asset_count    INTEGER DEFAULT 0,
    last_error     TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS observed_assets (
    fingerprint    TEXT PRIMARY KEY,
    platform       TEXT NOT NULL,
    program_id     TEXT NOT NULL,
    program_name   TEXT,
    program_url    TEXT,
    asset          TEXT NOT NULL,
    asset_type     TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    source_url     TEXT
);

CREATE TABLE IF NOT EXISTS fresh_candidates (
    fingerprint    TEXT PRIMARY KEY,
    platform       TEXT NOT NULL,
    program_id     TEXT NOT NULL,
    program_name   TEXT,
    program_url    TEXT,
    asset          TEXT NOT NULL,
    asset_type     TEXT,
    discovered_at  TEXT NOT NULL,
    status         TEXT DEFAULT 'queued',
    reason         TEXT DEFAULT '',
    scan_id        TEXT DEFAULT '',
    source_url     TEXT
);

CREATE TABLE IF NOT EXISTS authorizations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    platform        TEXT NOT NULL,
    program_id      TEXT NOT NULL,
    asset_patterns  TEXT NOT NULL,
    confirmed_at    TEXT NOT NULL,
    enabled         INTEGER DEFAULT 1,
    UNIQUE(platform, program_id)
);

CREATE TABLE IF NOT EXISTS monitor_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT,
    new_assets      INTEGER DEFAULT 0,
    scans_started   INTEGER DEFAULT 0,
    details_json    TEXT DEFAULT '{}'
);
"""


@dataclass
class FreshScopeConfig:
    enabled: bool = False
    auto_launch: bool = False
    interval_seconds: int = 24 * 60 * 60
    max_new_assets_per_run: int = 100
    max_scans_per_run: int = 5
    request_timeout_seconds: int = 20
    chaos_enabled: bool = True


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def configured_feeds() -> dict[str, str]:
    feeds = dict(DEFAULT_FEEDS)
    bbradar_url = _safe_text(os.getenv("BBRADAR_FEED_URL"))
    if bbradar_url.startswith(("https://", "http://")):
        feeds["bbradar"] = bbradar_url
    return feeds


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _program_id(program: dict, platform: str) -> str:
    return _safe_text(
        program.get("handle")
        or program.get("code")
        or program.get("id")
        or program.get("uuid")
        or program.get("name")
        or platform
    )


def _asset_value(item: Any) -> str:
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return ""
    return _safe_text(
        item.get("asset_identifier")
        or item.get("endpoint")
        or item.get("target")
        or item.get("uri")
        or item.get("url")
        or item.get("domain")
        or item.get("name")
    )


def _asset_type(item: Any) -> str:
    if not isinstance(item, dict):
        return "unknown"
    return _safe_text(
        item.get("asset_type")
        or item.get("type")
        or item.get("category")
        or "unknown"
    ).lower()


def _looks_web_scannable(asset: str, asset_type: str = "") -> bool:
    value = _safe_text(asset)
    if not value or " " in value or len(value) > 500:
        return False
    lowered_type = _safe_text(asset_type).lower()
    if any(
        token in lowered_type
        for token in ("android", "ios", "mobile", "hardware", "other", "source")
    ):
        return False
    parsed = urlparse(value if "://" in value else "https://" + value.lstrip("*."))
    host = parsed.hostname or ""
    return bool(host and ("." in host or host == "localhost"))


def _in_scope_items(program: dict) -> list[Any]:
    targets = program.get("targets")
    if isinstance(targets, dict):
        for key in ("in_scope", "inScope", "allowed", "eligible"):
            if isinstance(targets.get(key), list):
                return targets[key]
    for key in (
        "structured_scopes",
        "in_scope",
        "inScope",
        "targets",
        "assets",
        "scope",
    ):
        value = program.get(key)
        if isinstance(value, list):
            return value
    return []


def _out_of_scope_items(program: dict) -> list[Any]:
    targets = program.get("targets")
    if isinstance(targets, dict):
        for key in ("out_of_scope", "outOfScope", "disallowed", "excluded"):
            if isinstance(targets.get(key), list):
                return targets[key]
    for key in ("out_of_scope", "outOfScope", "disallowed_assets", "excluded"):
        value = program.get(key)
        if isinstance(value, list):
            return value
    return []


def _eligible(item: Any) -> bool:
    if not isinstance(item, dict):
        return True
    return bool(
        item.get(
            "eligible_for_submission",
            item.get("eligible", item.get("in_scope", True)),
        )
    )


def parse_scope_feed(platform: str, payload: Any, source_url: str = "") -> list[dict]:
    """Normalize common public bounty scope dump shapes."""
    if isinstance(payload, dict):
        programs = (
            payload.get("programs")
            or payload.get("data")
            or payload.get("results")
            or payload.get("items")
            or []
        )
        if not programs and any(
            key in payload for key in ("targets", "structured_scopes", "assets")
        ):
            programs = [payload]
    elif isinstance(payload, list):
        programs = payload
    else:
        programs = []

    records = []
    seen = set()
    for program in programs:
        if not isinstance(program, dict):
            continue
        status = _safe_text(
            program.get("status")
            or program.get("submission_state")
            or program.get("state")
        ).lower()
        confidentiality = _safe_text(
            program.get("confidentiality_level")
            or program.get("visibility")
        ).lower()
        if status in {"closed", "paused", "disabled", "archived"}:
            continue
        if confidentiality in {"private", "invite_only", "invite-only"}:
            continue
        program_id = _program_id(program, platform)
        program_name = _safe_text(program.get("name") or program.get("title") or program_id)
        program_url = _safe_text(
            program.get("url")
            or program.get("program_url")
            or program.get("policy_url")
        )
        excluded_assets = {
            _asset_value(item).lower().rstrip("/")
            for item in _out_of_scope_items(program)
            if _asset_value(item)
        }
        for item in _in_scope_items(program):
            if not _eligible(item):
                continue
            asset = _asset_value(item)
            asset_type = _asset_type(item)
            if not _looks_web_scannable(asset, asset_type):
                continue
            if asset.lower().rstrip("/") in excluded_assets:
                continue
            fingerprint = "{}|{}|{}".format(
                platform.lower(),
                program_id.lower(),
                asset.lower().rstrip("/"),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            records.append(
                {
                    "fingerprint": fingerprint,
                    "platform": platform.lower(),
                    "program_id": program_id,
                    "program_name": program_name,
                    "program_url": program_url,
                    "asset": asset,
                    "asset_type": asset_type,
                    "source_url": source_url,
                }
            )
    return records


def asset_to_target(asset: str) -> str:
    value = _safe_text(asset)
    if not value or value.startswith("*.") or "*" in value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        return ""
    return "{}://{}{}".format(
        parsed.scheme or "https",
        parsed.netloc,
        parsed.path if parsed.path and parsed.path != "/" else "",
    )


def _pattern_host(pattern: str) -> str:
    value = _safe_text(pattern).lower()
    parsed = urlparse(value if "://" in value else "https://" + value.lstrip("*."))
    host = parsed.hostname or value
    return ("*." if value.startswith("*.") else "") + host


class FreshScopeHunter:
    def __init__(self, db_path: str | None = None, config_path: str | None = None):
        base_dir = Path(os.path.expanduser("~/.burpollama"))
        self.db_path = Path(db_path) if db_path else base_dir / "fresh_scope_hunter.db"
        self.config_path = (
            Path(config_path) if config_path else base_dir / "fresh_scope_hunter.json"
        )
        self.config = FreshScopeConfig()
        self._stop_event = asyncio.Event()
        self._wake_event = asyncio.Event()
        self._run_lock = asyncio.Lock()
        self._load_config()
        self._ensure_db()

    def _ensure_db(self) -> None:
        try:
            self._initialize_db(self.db_path)
        except (OSError, sqlite3.OperationalError):
            fallback = Path(tempfile.gettempdir()) / "burpollama"
            self.db_path = fallback / "fresh_scope_hunter.db"
            self._initialize_db(self.db_path)

    def _initialize_db(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(DDL)
            connection.commit()

    @contextmanager
    def _conn(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _load_config(self) -> None:
        try:
            if self.config_path.exists():
                raw = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.update_config(raw, persist=False)
        except Exception:
            self.config = FreshScopeConfig()

    def update_config(self, values: dict, persist: bool = True) -> dict:
        current = asdict(self.config)
        for key, value in (values or {}).items():
            if key not in current:
                continue
            if isinstance(current[key], bool):
                current[key] = bool(value)
            elif isinstance(current[key], int):
                current[key] = max(1, int(value))
        current["interval_seconds"] = max(3600, current["interval_seconds"])
        current["max_new_assets_per_run"] = min(
            1000, current["max_new_assets_per_run"]
        )
        current["max_scans_per_run"] = min(50, current["max_scans_per_run"])
        self.config = FreshScopeConfig(**current)
        self._wake_event.set()
        if persist:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(
                json.dumps(asdict(self.config), indent=2),
                encoding="utf-8",
            )
        return self.status()

    def authorize(
        self,
        platform: str,
        program_id: str,
        asset_patterns: list[str],
    ) -> dict:
        platform = _safe_text(platform).lower()
        program_id = _safe_text(program_id)
        patterns = [
            _safe_text(pattern).lower().rstrip("/")
            for pattern in asset_patterns or []
            if _safe_text(pattern)
        ]
        if not platform or not program_id or not patterns:
            raise ValueError("Platform, program_id, and asset_patterns are required.")
        with self._conn() as connection:
            connection.execute(
                """
                INSERT INTO authorizations
                  (platform, program_id, asset_patterns, confirmed_at, enabled)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(platform, program_id) DO UPDATE SET
                  asset_patterns=excluded.asset_patterns,
                  confirmed_at=excluded.confirmed_at,
                  enabled=1
                """,
                (platform, program_id, json.dumps(patterns), _utcnow()),
            )
        return {
            "platform": platform,
            "program_id": program_id,
            "asset_patterns": patterns,
            "authorized": True,
        }

    def revoke(self, platform: str, program_id: str) -> bool:
        with self._conn() as connection:
            cursor = connection.execute(
                """
                UPDATE authorizations SET enabled=0
                WHERE platform=? AND program_id=?
                """,
                (_safe_text(platform).lower(), _safe_text(program_id)),
            )
        return bool(cursor.rowcount)

    def _authorizations(self) -> list[dict]:
        with self._conn() as connection:
            rows = connection.execute(
                """
                SELECT platform, program_id, asset_patterns, confirmed_at, enabled
                FROM authorizations ORDER BY confirmed_at DESC
                """
            ).fetchall()
        return [
            {
                "platform": row["platform"],
                "program_id": row["program_id"],
                "asset_patterns": json.loads(row["asset_patterns"] or "[]"),
                "confirmed_at": row["confirmed_at"],
                "enabled": bool(row["enabled"]),
            }
            for row in rows
        ]

    def _authorization_for(self, record: dict) -> dict | None:
        platform = _safe_text(record.get("platform")).lower()
        program_id = _safe_text(record.get("program_id"))
        asset = _safe_text(record.get("asset")).lower().rstrip("/")
        for authorization in self._authorizations():
            if not authorization["enabled"]:
                continue
            if authorization["platform"] != platform:
                continue
            if authorization["program_id"] not in {"*", program_id}:
                continue
            if any(
                fnmatch.fnmatch(asset, pattern)
                or fnmatch.fnmatch(
                    (urlparse(asset).hostname or asset).lower(),
                    _pattern_host(pattern),
                )
                for pattern in authorization["asset_patterns"]
            ):
                return authorization
        return None

    def candidates(self, limit: int = 100, status: str = "") -> list[dict]:
        query = "SELECT * FROM fresh_candidates"
        params: list[Any] = []
        if status:
            query += " WHERE status=?"
            params.append(status)
        query += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(max(1, min(1000, int(limit))))
        with self._conn() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def _feed_status(self) -> list[dict]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT * FROM feed_state ORDER BY platform"
            ).fetchall()
        return [dict(row) for row in rows]

    def status(self) -> dict:
        with self._conn() as connection:
            counts = {
                row["status"]: int(row["count"])
                for row in connection.execute(
                    """
                    SELECT status, COUNT(*) AS count
                    FROM fresh_candidates GROUP BY status
                    """
                ).fetchall()
            }
            last_run = connection.execute(
                "SELECT * FROM monitor_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        last_run_data = dict(last_run) if last_run else None
        if last_run_data:
            try:
                last_run_data["details"] = json.loads(
                    last_run_data.pop("details_json") or "{}"
                )
            except Exception:
                last_run_data["details"] = {}
        return {
            "config": asdict(self.config),
            "feeds": self._feed_status(),
            "configured_sources": sorted(configured_feeds()),
            "candidate_counts": counts,
            "recent_candidates": self.candidates(limit=25),
            "authorizations": self._authorizations(),
            "last_run": last_run_data,
            "chaos": {
                "installed": bool(shutil.which("chaos")),
                "api_key_configured": bool(os.getenv("PDCP_API_KEY")),
                "enabled": self.config.chaos_enabled,
            },
            "safety": {
                "first_fetch_is_baseline_only": True,
                "public_scope_is_advisory": True,
                "authorization_required_for_auto_launch": True,
                "central_scope_policy_must_also_allow_target": True,
                "active_testing_inherited_from_scope_policy": True,
            },
            "db_path": str(self.db_path),
        }

    async def _fetch_feed(
        self,
        client: httpx.AsyncClient,
        platform: str,
        source_url: str,
    ) -> tuple[list[dict], dict]:
        with self._conn() as connection:
            previous = connection.execute(
                "SELECT * FROM feed_state WHERE platform=?",
                (platform,),
            ).fetchone()
        headers = {}
        if previous and previous["etag"]:
            headers["If-None-Match"] = previous["etag"]
        if previous and previous["last_modified"]:
            headers["If-Modified-Since"] = previous["last_modified"]
        checked_at = _utcnow()
        try:
            response = await client.get(source_url, headers=headers)
            if response.status_code == 304:
                with self._conn() as connection:
                    connection.execute(
                        "UPDATE feed_state SET last_checked=?, last_error='' "
                        "WHERE platform=?",
                        (checked_at, platform),
                    )
                return [], {"platform": platform, "unchanged": True}
            response.raise_for_status()
            records = parse_scope_feed(platform, response.json(), source_url)
            with self._conn() as connection:
                connection.execute(
                    """
                    INSERT INTO feed_state
                      (platform, etag, last_modified, last_checked, last_success,
                       asset_count, last_error)
                    VALUES (?, ?, ?, ?, ?, ?, '')
                    ON CONFLICT(platform) DO UPDATE SET
                      etag=excluded.etag,
                      last_modified=excluded.last_modified,
                      last_checked=excluded.last_checked,
                      last_success=excluded.last_success,
                      asset_count=excluded.asset_count,
                      last_error=''
                    """,
                    (
                        platform,
                        response.headers.get("etag", ""),
                        response.headers.get("last-modified", ""),
                        checked_at,
                        checked_at,
                        len(records),
                    ),
                )
            return records, {
                "platform": platform,
                "records": len(records),
                "baseline": previous is None or not previous["last_success"],
            }
        except Exception as exc:
            with self._conn() as connection:
                connection.execute(
                    """
                    INSERT INTO feed_state
                      (platform, last_checked, last_error)
                    VALUES (?, ?, ?)
                    ON CONFLICT(platform) DO UPDATE SET
                      last_checked=excluded.last_checked,
                      last_error=excluded.last_error
                    """,
                    (platform, checked_at, str(exc)[:500]),
                )
            return [], {"platform": platform, "error": str(exc)}

    def _store_records(
        self,
        platform: str,
        records: list[dict],
        *,
        baseline: bool,
    ) -> list[dict]:
        now = _utcnow()
        fresh = []
        with self._conn() as connection:
            for record in records:
                exists = connection.execute(
                    "SELECT 1 FROM observed_assets WHERE fingerprint=?",
                    (record["fingerprint"],),
                ).fetchone()
                connection.execute(
                    """
                    INSERT INTO observed_assets
                      (fingerprint, platform, program_id, program_name,
                       program_url, asset, asset_type, first_seen, last_seen,
                       source_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                      last_seen=excluded.last_seen,
                      program_url=excluded.program_url,
                      source_url=excluded.source_url
                    """,
                    (
                        record["fingerprint"],
                        platform,
                        record["program_id"],
                        record["program_name"],
                        record["program_url"],
                        record["asset"],
                        record["asset_type"],
                        now,
                        now,
                        record["source_url"],
                    ),
                )
                if exists or baseline:
                    continue
                connection.execute(
                    """
                    INSERT OR IGNORE INTO fresh_candidates
                      (fingerprint, platform, program_id, program_name,
                       program_url, asset, asset_type, discovered_at,
                       source_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["fingerprint"],
                        platform,
                        record["program_id"],
                        record["program_name"],
                        record["program_url"],
                        record["asset"],
                        record["asset_type"],
                        now,
                        record["source_url"],
                    ),
                )
                fresh.append(record)
        return fresh

    async def chaos_subdomains(self, domain: str, limit: int = 100) -> list[str]:
        if (
            not self.config.chaos_enabled
            or not shutil.which("chaos")
            or not os.getenv("PDCP_API_KEY")
        ):
            return []
        clean_domain = _safe_text(domain).lower().lstrip("*.")
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", clean_domain):
            return []
        try:
            process = await asyncio.create_subprocess_exec(
                "chaos",
                "-d",
                clean_domain,
                "-silent",
                "-duc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
            if process.returncode != 0:
                return []
            hosts = []
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                host = line.strip().lower().strip(".")
                if host == clean_domain or host.endswith("." + clean_domain):
                    hosts.append(host)
                if len(hosts) >= limit:
                    break
            return list(dict.fromkeys(hosts))
        except Exception:
            return []

    def _mark_candidate(
        self,
        fingerprint: str,
        status: str,
        reason: str = "",
        scan_id: str = "",
    ) -> None:
        with self._conn() as connection:
            connection.execute(
                """
                UPDATE fresh_candidates
                SET status=?, reason=?, scan_id=?
                WHERE fingerprint=?
                """,
                (status, reason[:500], scan_id, fingerprint),
            )

    async def check_now(
        self,
        scan_launcher: Callable[[dict, str], Awaitable[str | None]] | None = None,
    ) -> dict:
        if self._run_lock.locked():
            return {"status": "already_running", "new_assets": 0, "scans_started": 0}
        async with self._run_lock:
            started = _utcnow()
            with self._conn() as connection:
                cursor = connection.execute(
                    "INSERT INTO monitor_runs (started_at, status) VALUES (?, ?)",
                    (started, "running"),
                )
                run_id = int(cursor.lastrowid)

            details = []
            fresh_records = []
            timeout = httpx.Timeout(
                float(self.config.request_timeout_seconds),
                connect=min(10.0, float(self.config.request_timeout_seconds)),
            )
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "BurpOllama/3.1 fresh-scope-monitor",
                    "Accept": "application/json",
                },
            ) as client:
                feeds = configured_feeds()
                results = await asyncio.gather(
                    *(
                        self._fetch_feed(client, platform, source_url)
                        for platform, source_url in feeds.items()
                    )
                )
            for (records, feed_detail), (platform, _) in zip(
                results, feeds.items()
            ):
                details.append(feed_detail)
                fresh_records.extend(
                    self._store_records(
                        platform,
                        records,
                        baseline=bool(feed_detail.get("baseline")),
                    )
                )

            fresh_records = fresh_records[: self.config.max_new_assets_per_run]
            scans_started = 0
            if self.config.auto_launch and scan_launcher:
                retryable_statuses = {
                    "queued",
                    "awaiting_authorization",
                    "blocked_by_scope",
                    "needs_specific_host",
                    "launch_failed",
                }
                launch_queue = []
                queued_fingerprints = set()
                for record in fresh_records + self.candidates(limit=1000):
                    if record.get("status", "queued") not in retryable_statuses:
                        continue
                    fingerprint = record.get("fingerprint", "")
                    if not fingerprint or fingerprint in queued_fingerprints:
                        continue
                    queued_fingerprints.add(fingerprint)
                    launch_queue.append(record)
                for record in launch_queue:
                    if scans_started >= self.config.max_scans_per_run:
                        break
                    authorization = self._authorization_for(record)
                    if not authorization:
                        self._mark_candidate(
                            record["fingerprint"],
                            "awaiting_authorization",
                            "No matching confirmed program authorization.",
                        )
                        continue
                    target = asset_to_target(record["asset"])
                    targets = [target] if target else []
                    if not targets and record["asset"].startswith("*."):
                        domain = record["asset"][2:]
                        targets = [
                            "https://" + host
                            for host in await self.chaos_subdomains(
                                domain,
                                limit=max(
                                    1,
                                    self.config.max_scans_per_run - scans_started,
                                ),
                            )
                        ]
                    if not targets:
                        self._mark_candidate(
                            record["fingerprint"],
                            "needs_specific_host",
                            "Wildcard or non-runnable asset requires a specific "
                            "authorized host; optional Chaos enrichment returned none.",
                        )
                        continue
                    scan_ids = []
                    blocked = 0
                    for candidate_target in targets:
                        if scans_started >= self.config.max_scans_per_run:
                            break
                        try:
                            scan_id = await scan_launcher(record, candidate_target)
                        except Exception as exc:
                            self._mark_candidate(
                                record["fingerprint"],
                                "launch_failed",
                                str(exc),
                            )
                            continue
                        if scan_id:
                            scans_started += 1
                            scan_ids.append(scan_id)
                        else:
                            blocked += 1
                    if scan_ids:
                        self._mark_candidate(
                            record["fingerprint"],
                            "scan_started",
                            "Matched confirmed authorization and central scope policy.",
                            ",".join(scan_ids),
                        )
                    elif blocked:
                        self._mark_candidate(
                            record["fingerprint"],
                            "blocked_by_scope",
                            "Central ScopePolicy did not authorize this target.",
                        )

            finished = _utcnow()
            summary = {
                "status": "complete",
                "started_at": started,
                "finished_at": finished,
                "new_assets": len(fresh_records),
                "scans_started": scans_started,
                "feeds": details,
            }
            with self._conn() as connection:
                connection.execute(
                    """
                    UPDATE monitor_runs SET finished_at=?, status='complete',
                      new_assets=?, scans_started=?, details_json=?
                    WHERE id=?
                    """,
                    (
                        finished,
                        len(fresh_records),
                        scans_started,
                        json.dumps(details),
                        run_id,
                    ),
                )
            return summary

    async def run_forever(
        self,
        scan_launcher: Callable[[dict, str], Awaitable[str | None]] | None = None,
    ) -> None:
        next_run = 0.0
        while not self._stop_event.is_set():
            now = time.monotonic()
            if self.config.enabled and now >= next_run:
                try:
                    await self.check_now(scan_launcher)
                except Exception:
                    pass
                next_run = time.monotonic() + self.config.interval_seconds
            wait_seconds = (
                max(1.0, next_run - time.monotonic())
                if self.config.enabled
                else 3600.0
            )
            self._wake_event.clear()
            try:
                await asyncio.wait_for(
                    self._wake_event.wait(),
                    timeout=wait_seconds,
                )
            except asyncio.TimeoutError:
                continue
            if self.config.enabled:
                next_run = 0.0

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()


fresh_scope_hunter = FreshScopeHunter()
