"""Passive recon expansion helpers.

These helpers intentionally stay generic and passive. They collect public
certificate/search/archive/DNS signals, filter them through caller-provided
scope checks, and never brute force names or paths.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse

import httpx

from core.ratelimit import RateLimiter


AllowFn = Callable[[str], bool]


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<name>[A-Za-z0-9_$-]*(?:api[_-]?key|apikey|token|secret|bearer)[A-Za-z0-9_$-]*)\b"
    r"\s*[:=]\s*"
    r"(?P<quote>['\"])(?P<value>(?:(?!(?P=quote)).){8,200})(?P=quote)"
)
S3_HOST_RE = re.compile(
    r"(?i)\b(?:[a-z0-9][a-z0-9.-]{1,61}\.)?s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b|"
    r"\bs3\.amazonaws\.com/[A-Za-z0-9._/-]+"
)
INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:localhost|(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:internal|local|corp|lan))\b"
)
DANGLING_CNAME_PATTERNS = (
    "amazonaws.com",
    "azurewebsites.net",
    "cloudapp.net",
    "github.io",
    "herokuapp.com",
    "pages.dev",
    "readme.io",
    "surge.sh",
    "trafficmanager.net",
)


@dataclass
class DNSFinding:
    host: str
    kind: str
    status: str
    evidence: str
    cname_chain: list[str]
    ttl: int | None = None


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def domain_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return (parsed.hostname or "").lower().strip(".")


def normalize_subdomain(value: str, root_domain: str) -> str | None:
    candidate = (value or "").strip().lower().strip("*.").strip(".")
    root = (root_domain or "").lower().strip(".")
    if not candidate or not root:
        return None
    if candidate == root or candidate.endswith("." + root):
        return candidate
    return None


def parse_crtsh_json(text: str, root_domain: str) -> list[str]:
    try:
        rows = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = str(row.get("name_value") or row.get("common_name") or "")
        for name in re.split(r"[\s,]+", names):
            normalized = normalize_subdomain(name, root_domain)
            if normalized:
                found.append(normalized)
    return list(dict.fromkeys(found))


def parse_hackertarget_hostsearch(text: str, root_domain: str) -> list[str]:
    found: list[str] = []
    for line in (text or "").splitlines():
        host = line.split(",", 1)[0].strip()
        normalized = normalize_subdomain(host, root_domain)
        if normalized:
            found.append(normalized)
    return list(dict.fromkeys(found))


def parse_wayback_urls(text: str, root_domain: str, allows: AllowFn) -> list[str]:
    try:
        rows = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    values: Iterable = rows[1:] if rows and rows[0] == ["original"] else rows
    urls: list[str] = []
    for row in values:
        original = row[0] if isinstance(row, list) and row else row
        if not isinstance(original, str):
            continue
        parsed = urlparse(original)
        host = (parsed.hostname or "").lower().strip(".")
        if not (host == root_domain or host.endswith("." + root_domain)):
            continue
        if allows(original):
            urls.append(original)
    return list(dict.fromkeys(urls))


def extract_js_intelligence(js_text: str) -> dict[str, list[dict]]:
    secrets = []
    for match in SECRET_ASSIGNMENT_RE.finditer(js_text or ""):
        value = match.group("value")
        # Avoid turning minified option flags or obvious placeholders into noise.
        if value.lower() in {"true", "false", "undefined", "null", "changeme"}:
            continue
        if len(set(value)) < 4:
            continue
        secrets.append({
            "name": match.group("name"),
            "value_preview": value[:6] + "…" if len(value) > 6 else value,
            "offset": match.start("value"),
            "matched_indicator": match.group(0)[:120],
        })
    buckets = [
        {"value": match.group(0), "offset": match.start()}
        for match in S3_HOST_RE.finditer(js_text or "")
    ]
    internal_hosts = [
        {"value": match.group(0), "offset": match.start()}
        for match in INTERNAL_HOST_RE.finditer(js_text or "")
    ]
    return {
        "secrets": _dedupe_dicts(secrets, "matched_indicator"),
        "s3_buckets": _dedupe_dicts(buckets, "value"),
        "internal_hosts": _dedupe_dicts(internal_hosts, "value"),
    }


def _dedupe_dicts(items: list[dict], key: str) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        marker = item.get(key)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


async def fetch_passive_subdomains(domain: str, client: httpx.AsyncClient, limiter: RateLimiter) -> dict:
    if is_ip_address(domain):
        return {"subdomains": [], "sources": {}, "errors": {}}
    sources = {
        "crtsh": "https://crt.sh/?q=%.{}&output=json".format(domain),
        "hackertarget": "https://api.hackertarget.com/hostsearch/?q={}".format(domain),
    }
    discovered: list[str] = []
    raw_sources: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for source, url in sources.items():
        await limiter.acquire()
        try:
            response = await client.get(url, timeout=12)
            response.raise_for_status()
            if source == "crtsh":
                parsed = parse_crtsh_json(response.text, domain)
            else:
                parsed = parse_hackertarget_hostsearch(response.text, domain)
            raw_sources[source] = parsed
            discovered.extend(parsed)
        except Exception as exc:
            errors[source] = type(exc).__name__
    return {
        "subdomains": list(dict.fromkeys(discovered)),
        "sources": raw_sources,
        "errors": errors,
    }


async def fetch_wayback_urls(domain: str, client: httpx.AsyncClient, limiter: RateLimiter, allows: AllowFn) -> dict:
    if is_ip_address(domain):
        return {"urls": [], "errors": {}}
    url = (
        "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json"
        "&collapse=urlkey&fl=original&limit=500"
    ).format(domain)
    await limiter.acquire()
    try:
        response = await client.get(url, timeout=15)
        response.raise_for_status()
        urls = parse_wayback_urls(response.text, domain, allows)
        return {"urls": urls, "errors": {}}
    except Exception as exc:
        return {"urls": [], "errors": {"wayback": type(exc).__name__}}


def build_urls_for_subdomains(subdomains: list[str], scheme: str = "https") -> list[str]:
    return ["{}://{}".format(scheme or "https", host) for host in subdomains]


async def check_dns_misconfigurations(domain: str, subdomains: list[str]) -> list[DNSFinding]:
    findings: list[DNSFinding] = []
    if is_ip_address(domain):
        return findings
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return await _socket_dns_fallback(domain, subdomains)

    resolver = dns.resolver.Resolver()
    hosts = list(dict.fromkeys(subdomains))[:100]
    for host in hosts:
        try:
            answers = await asyncio.to_thread(resolver.resolve, host, "CNAME")
        except Exception:
            continue
        chain = [str(item.target).rstrip(".") for item in answers]
        ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
        if any(_looks_dangling_cname(cname) for cname in chain):
            findings.append(DNSFinding(
                host=host,
                kind="dangling_cname_candidate",
                status="candidate",
                evidence="CNAME chain references external service: {}".format(", ".join(chain)),
                cname_chain=chain,
                ttl=ttl,
            ))
    for record_type, policy_name in (("TXT", "SPF"), ("TXT", "DMARC")):
        query = domain if policy_name == "SPF" else "_dmarc." + domain
        try:
            answers = await asyncio.to_thread(resolver.resolve, query, record_type)
            values = [
                b"".join(getattr(item, "strings", [])).decode("utf-8", "ignore")
                for item in answers
            ]
        except Exception:
            values = []
        if policy_name == "SPF" and not any(value.lower().startswith("v=spf1") for value in values):
            findings.append(DNSFinding(domain, "missing_spf", "info", "No SPF TXT record observed", [], None))
        if policy_name == "DMARC" and not any(value.lower().startswith("v=dmarc1") for value in values):
            findings.append(DNSFinding(domain, "missing_dmarc", "info", "No DMARC TXT record observed", [], None))
    return findings


async def _socket_dns_fallback(domain: str, subdomains: list[str]) -> list[DNSFinding]:
    findings: list[DNSFinding] = []
    for host in list(dict.fromkeys(subdomains))[:50]:
        try:
            await asyncio.to_thread(socket.getaddrinfo, host, None)
        except OSError:
            findings.append(DNSFinding(host, "unresolved_subdomain", "candidate", "Host did not resolve via socket fallback", [], None))
    return findings


def _looks_dangling_cname(value: str) -> bool:
    lowered = (value or "").lower().rstrip(".")
    return any(pattern in lowered for pattern in DANGLING_CNAME_PATTERNS)


def absolutize_url(base_url: str, value: str) -> str:
    return urljoin(base_url, value)
