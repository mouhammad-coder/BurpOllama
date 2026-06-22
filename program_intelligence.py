"""Public bug-bounty program and vulnerability intelligence.

All remote lookups are optional, bounded, cached, and fail closed to empty
results so intelligence outages never interrupt an authorized scan.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx


CACHE_TTL_SECONDS = 24 * 60 * 60
CACHE_PATH = Path(os.path.expanduser("~/.burpollama/program_intelligence.db"))
HEADERS = {
    "User-Agent": "BurpOllama/3.0 public-security-intelligence",
    "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
}


def _cache_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return "{}:{}".format(namespace, digest)


def _cache_get(key: str) -> Any | None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(CACHE_PATH)) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS intelligence_cache "
                "(cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            row = connection.execute(
                "SELECT payload, created_at FROM intelligence_cache WHERE cache_key=?",
                (key,),
            ).fetchone()
        if not row or time.time() - float(row[1]) > CACHE_TTL_SECONDS:
            return None
        return json.loads(row[0])
    except Exception:
        return None


def _cache_set(key: str, payload: Any) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(CACHE_PATH)) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS intelligence_cache "
                "(cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            connection.execute(
                "INSERT OR REPLACE INTO intelligence_cache "
                "(cache_key, payload, created_at) VALUES (?, ?, ?)",
                (key, json.dumps(payload, ensure_ascii=False), time.time()),
            )
            connection.commit()
    except Exception:
        return


def _asset_identifier(asset: Any) -> str:
    if isinstance(asset, str):
        return asset
    if not isinstance(asset, dict):
        return ""
    return str(
        asset.get("asset_identifier")
        or asset.get("identifier")
        or asset.get("asset")
        or asset.get("name")
        or ""
    )


def _normalize_policy(data: dict, slug: str) -> dict:
    scopes = (
        data.get("structured_scopes")
        or data.get("scope")
        or data.get("assets")
        or []
    )
    allowed_assets = []
    disallowed_assets = []
    for asset in scopes if isinstance(scopes, list) else []:
        identifier = _asset_identifier(asset)
        if not identifier:
            continue
        eligible = True
        if isinstance(asset, dict):
            eligible = bool(
                asset.get("eligible_for_submission", asset.get("eligible", True))
            )
        (allowed_assets if eligible else disallowed_assets).append(identifier)
    bounty_table = (
        data.get("bounty_table")
        or data.get("bounties")
        or data.get("bounty_ranges")
        or {}
    )
    return {
        "allowed_assets": list(dict.fromkeys(allowed_assets)),
        "disallowed_assets": list(dict.fromkeys(disallowed_assets)),
        "bounty_table": bounty_table,
        "program_url": "https://hackerone.com/{}".format(slug),
        "response_time_history": data.get("response_time_history")
        or data.get("response_time")
        or {},
        "raw_program_name": data.get("name") or data.get("handle") or slug,
    }


async def fetch_hackerone_scope(program_slug: str) -> dict:
    slug = re.sub(r"[^A-Za-z0-9_.-]", "", str(program_slug or "").strip())
    if not slug:
        return {}
    key = _cache_key("h1-policy", slug.lower())
    cached = _cache_get(key)
    if isinstance(cached, dict):
        return cached
    url = "https://hackerone.com/programs/{}/policy.json".format(slug)
    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            response = await client.get(url)
        if response.status_code != 200:
            return {}
        data = response.json()
        if not isinstance(data, dict):
            return {}
        result = _normalize_policy(data, slug)
        _cache_set(key, result)
        return result
    except Exception:
        return {}


def _parse_disclosed_reports(document: str) -> list[dict]:
    reports = []
    seen = set()
    pattern = re.compile(
        r'href=["\']/reports/(\d+)["\'][^>]*>(.*?)</a>',
        re.I | re.S,
    )
    for report_id, raw_title in pattern.findall(document or ""):
        if report_id in seen:
            continue
        title = html.unescape(re.sub(r"<[^>]+>", " ", raw_title))
        title = re.sub(r"\s+", " ", title).strip()
        if not title:
            continue
        context_match = re.search(
            r"/reports/{}.{{0,1200}}".format(re.escape(report_id)),
            document,
            re.I | re.S,
        )
        context = re.sub(r"<[^>]+>", " ", context_match.group(0)) if context_match else ""
        severity_match = re.search(
            r"\b(Critical|High|Medium|Low|Informational)\b", context, re.I
        )
        payout_match = re.search(r"\$\s?[\d,]+(?:\.\d{2})?", context)
        reports.append({
            "report_id": report_id,
            "title": title[:300],
            "severity": severity_match.group(1).upper() if severity_match else "UNKNOWN",
            "payout": payout_match.group(0) if payout_match else "",
            "summary": re.sub(r"\s+", " ", context).strip()[:500],
        })
        seen.add(report_id)
        if len(reports) >= 5:
            break
    return reports


async def search_disclosed_reports(
    vuln_type: str,
    tech_stack: list,
) -> list:
    terms = [str(vuln_type or "").strip()] + [
        str(item).strip() for item in (tech_stack or [])[:3]
    ]
    query = " ".join(term for term in terms if term)
    if not query:
        return []
    key = _cache_key("h1-reports", query.lower())
    cached = _cache_get(key)
    if isinstance(cached, list):
        return cached[:5]
    url = "https://hackerone.com/reports?filter[keyword]={}".format(quote(query))
    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=httpx.Timeout(12.0, connect=5.0),
        ) as client:
            response = await client.get(url)
        if response.status_code != 200:
            return []
        result = _parse_disclosed_reports(response.text)[:5]
        _cache_set(key, result)
        return result
    except Exception:
        return []


async def lookup_nvd_cve(technology: str) -> list:
    technology = str(technology or "").strip()
    if not technology:
        return []
    key = _cache_key("nvd", technology.lower())
    cached = _cache_get(key)
    if isinstance(cached, list):
        return cached[:10]
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?keywordSearch={}".format(quote(technology))
    )
    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=httpx.Timeout(15.0, connect=5.0),
        ) as client:
            response = await client.get(url)
        if response.status_code != 200:
            return []
        payload = response.json()
        result = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {}) if isinstance(item, dict) else {}
            metrics = cve.get("metrics", {})
            metric_candidates = []
            for name in (
                "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"
            ):
                metric_candidates.extend(metrics.get(name, []) or [])
            severity = ""
            for metric in metric_candidates:
                severity = str(
                    metric.get("cvssData", {}).get("baseSeverity")
                    or metric.get("baseSeverity")
                    or ""
                ).upper()
                if severity:
                    break
            if severity not in {"CRITICAL", "HIGH"}:
                continue
            descriptions = cve.get("descriptions", [])
            english = next(
                (
                    entry.get("value", "")
                    for entry in descriptions
                    if entry.get("lang") == "en"
                ),
                "",
            )
            result.append({
                "cve_id": cve.get("id", ""),
                "severity": severity,
                "description": english[:1000],
                "published_date": cve.get("published", ""),
            })
            if len(result) >= 10:
                break
        _cache_set(key, result)
        return result
    except Exception:
        return []


def _maximum_bounty(value: Any) -> float:
    numbers = []
    if isinstance(value, dict):
        for nested in value.values():
            numbers.append(_maximum_bounty(nested))
    elif isinstance(value, list):
        for nested in value:
            numbers.append(_maximum_bounty(nested))
    else:
        for match in re.findall(r"\d[\d,]*(?:\.\d+)?", str(value or "")):
            try:
                numbers.append(float(match.replace(",", "")))
            except ValueError:
                pass
    return max(numbers, default=0.0)


def score_program_attractiveness(program_data: dict) -> dict:
    data = program_data or {}
    allowed = data.get("allowed_assets", []) or []
    score = 0
    ranked_assets = []
    for asset in allowed:
        name = _asset_identifier(asset) or str(asset)
        lower = name.lower()
        asset_score = 20
        if "*." in name:
            asset_score += 35
        if lower.startswith(("http://", "https://")) or "." in name:
            asset_score += 25
        if any(term in lower for term in ("api", "app", "web")):
            asset_score += 15
        if any(term in lower for term in ("mobile", "android", "ios")):
            asset_score += 8
        if any(term in lower for term in ("hardware", "device", "iot")):
            asset_score -= 5
        ranked_assets.append((asset_score, name))
    if allowed:
        score += min(45, max((item[0] for item in ranked_assets), default=0))
        score += min(10, len(allowed))

    maximum = _maximum_bounty(data.get("bounty_table", {}))
    if maximum >= 50_000:
        score += 30
    elif maximum >= 10_000:
        score += 24
    elif maximum >= 5_000:
        score += 18
    elif maximum > 0:
        score += 10

    response = data.get("response_time_history", {})
    response_text = json.dumps(response).lower()
    if any(term in response_text for term in ("excellent", "fast", "1 day", "2 day")):
        score += 15
    elif response:
        score += 8

    score = max(0, min(100, score))
    recommendation = (
        "High-priority program with broad, valuable attack surface."
        if score >= 75
        else "Promising program; review scope exclusions and reward tiers."
        if score >= 50
        else "Lower-priority program unless you have strong technology-specific expertise."
    )
    ranked_assets.sort(reverse=True)
    return {
        "score": score,
        "recommendation": recommendation,
        "best_assets": [name for _, name in ranked_assets[:10]],
    }
