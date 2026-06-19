"""
recon_engine.py — Automated recon pipeline
Phase 1 of the automated hunt.

Tool priority (falls back gracefully if not installed):
  Subdomains  : subfinder → fallback DNS brute
  Live probing: httpx     → fallback httpx-python
  URL crawl   : katana    → fallback requests-based crawler
  JS analysis : built-in  → always runs
  WAF detect  : wafw00f   → built-in header check
"""

import asyncio
import re
import shutil
import subprocess
import json
import httpx
import os
import tempfile
from typing import Callable
from urllib.parse import urljoin, urlparse
from scope_policy import scope_policy
from js_endpoint_extractor import extract_js_endpoints
from finding_model import normalize_finding

# ── Helpers ───────────────────────────────────────────────────────────────────

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None

async def run_cmd(cmd: list[str], timeout: int = 120) -> str:
    """Run a shell command async and return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode("utf-8", errors="ignore")
        except asyncio.TimeoutError:
            proc.kill()
            return ""
    except Exception as e:
        print("[ReconEngine] cmd error {}: {}".format(cmd[0], e))
        return ""


async def _nuclei_log(log: Callable, message: str, level: str = "info"):
    try:
        result = log(message, level)
    except TypeError:
        result = log(message)
    if asyncio.iscoroutine(result):
        await result


def _nuclei_cwe(info: dict, raw: dict) -> str:
    classification = info.get("classification") or {}
    values = classification.get("cwe-id") or classification.get("cwe_id") or []
    if isinstance(values, str):
        values = [values]
    text = " ".join(
        [str(value) for value in values]
        + [str(info.get("tags", "")), str(raw.get("template-id", ""))]
    )
    match = re.search(r"(?i)\bCWE[-_: ]?(\d+)\b", text)
    return "CWE-{}".format(match.group(1)) if match else ""


def _nuclei_evidence(raw: dict) -> str:
    response = raw.get("response") or raw.get("matched-response") or ""
    if response:
        return str(response)[:1500]
    extracted = raw.get("extracted-results") or raw.get("extracted_results") or []
    if extracted:
        return "Extracted results: {}".format(
            ", ".join(str(value) for value in extracted[:10])
        )[:1500]
    return "Template {} matched via matcher {}.".format(
        raw.get("template-id", "unknown"),
        raw.get("matcher-name") or raw.get("matcher_name") or "default",
    )


def _nuclei_method(raw: dict) -> str:
    request = str(raw.get("request") or "")
    match = re.match(r"(?i)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", request)
    return match.group(1).upper() if match else "GET"


async def run_nuclei_scan(
    live_hosts: list,
    scope_policy,
    log: Callable,
) -> list[dict]:
    """Run a bounded nuclei supplement and normalize its JSONL findings."""
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        await _nuclei_log(
            log,
            "[Nuclei] nuclei is not installed — skipping Phase 2 supplement.",
            "warning",
        )
        return []

    policy = scope_policy
    if not policy.config.active_testing_enabled or policy.config.passive_only_mode:
        await _nuclei_log(
            log,
            "[Nuclei] active testing is disabled by ScopePolicy — skipping.",
            "warning",
        )
        return []

    host_urls = []
    for host in live_hosts or []:
        url = str(host.get("url", "") if isinstance(host, dict) else host)
        if not url or url in host_urls:
            continue
        allowed, _reason = policy.validate_target(url, action="active")
        if allowed:
            host_urls.append(url)
    if not host_urls:
        await _nuclei_log(log, "[Nuclei] no in-scope live hosts to scan.", "warning")
        return []

    hosts_file = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".txt",
            prefix="burpollama-nuclei-",
            delete=False,
        ) as handle:
            hosts_file = handle.name
            handle.write("\n".join(host_urls))
            handle.write("\n")

        command = [
            nuclei_path,
            "-l", hosts_file,
            "-t", "cves",
            "-t", "exposures",
            "-t", "misconfigurations",
            "-json",
            "-silent",
            "-rate-limit", "10",
            "-bulk-size", "5",
        ]
        await _nuclei_log(
            log,
            "[Nuclei] scanning {} in-scope live host(s).".format(len(host_urls)),
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            await _nuclei_log(
                log,
                "[Nuclei] scan timed out after 600 seconds.",
                "warning",
            )
            return []

        if process.returncode not in (0, None) and stderr:
            await _nuclei_log(
                log,
                "[Nuclei] exited with code {}: {}".format(
                    process.returncode,
                    stderr.decode("utf-8", errors="ignore")[:300],
                ),
                "warning",
            )

        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "unknown": "INFO",
        }
        findings = []
        seen = set()
        for line in stdout.decode("utf-8", errors="ignore").splitlines():
            try:
                raw = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(raw, dict):
                continue

            info = raw.get("info") or {}
            if not isinstance(info, dict):
                info = {}
            matched_url = str(
                raw.get("matched-at")
                or raw.get("matched")
                or raw.get("host")
                or raw.get("url")
                or ""
            )
            if not matched_url or not policy.validate_target(
                matched_url, action="active"
            )[0]:
                continue

            template_id = str(raw.get("template-id") or raw.get("template_id") or "")
            template_name = str(info.get("name") or template_id or "Nuclei Finding")
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tag_text = tags
            else:
                tag_text = ",".join(str(tag) for tag in tags)
            references = info.get("reference") or info.get("references") or []
            if isinstance(references, str):
                references = [references]
            metadata = info.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            cve_match = bool(
                re.search(r"(?i)\bCVE-\d{4}-\d+\b", template_id + " " + tag_text)
            )
            has_poc = bool(
                raw.get("request")
                or raw.get("response")
                or raw.get("extracted-results")
                or metadata.get("verified")
                or any("poc" in str(reference).lower() for reference in references)
            )
            exploitability = "probable" if cve_match and has_poc else "candidate"
            severity = severity_map.get(
                str(info.get("severity", "unknown")).lower(),
                "INFO",
            )
            evidence = _nuclei_evidence(raw)
            key = (template_id or template_name, matched_url)
            if key in seen:
                continue
            seen.add(key)

            findings.append(normalize_finding({
                "source": "nuclei",
                "title": template_name,
                "vuln_type": template_name,
                "vulnerability_class": "Nuclei Template Match",
                "severity": severity,
                "confidence": 85 if exploitability == "probable" else 65,
                "url": matched_url,
                "affected_url": matched_url,
                "method": _nuclei_method(raw),
                "description": str(info.get("description") or template_name),
                "evidence": evidence,
                "remediation": str(
                    info.get("remediation")
                    or "Review the matched nuclei template and apply the vendor-specific security fix."
                ),
                "cwe": _nuclei_cwe(info, raw),
                "references": [str(reference) for reference in references],
                "nuclei_template_id": template_id,
                "nuclei_tags": tag_text,
                "exploitability_status": exploitability,
                "evidence_strength": "moderate" if exploitability == "probable" else "weak",
                "false_positive_risk": "medium" if exploitability == "probable" else "high",
                "business_impact": str(
                    info.get("impact")
                    or "The matched exposure or vulnerable component may affect the confidentiality, integrity, or availability of the target."
                ),
                "technical_impact": str(info.get("description") or template_name),
                "reproduction_steps": [
                    "Review nuclei template '{}' and its matcher conditions.".format(
                        template_id or template_name
                    ),
                    "Send the template's non-destructive request to {} within authorized scope.".format(
                        matched_url
                    ),
                    "Confirm the matcher response shown in the captured evidence.",
                ],
                "redaction_status": "redacted",
            }))

        await _nuclei_log(
            log,
            "[Nuclei] supplement complete: {} finding(s).".format(len(findings)),
        )
        return findings
    except (OSError, asyncio.SubprocessError) as exc:
        await _nuclei_log(
            log,
            "[Nuclei] execution error: {}".format(exc),
            "warning",
        )
        return []
    finally:
        if hosts_file:
            try:
                os.unlink(hosts_file)
            except OSError:
                pass

# ── Phase 1a: Subdomain Enumeration ──────────────────────────────────────────

# Fix 6 (v3.4): Expanded from 30 to top-200 common subdomain prefixes.
# Covers dev infrastructure, cloud services, CI/CD, monitoring, auth, and APIs
# that are routinely missed by a 30-word list when passive sources fail.
FALLBACK_SUBS = [
    # Core
    "www", "api", "api2", "api3", "app", "apps", "web", "portal",
    # Dev / staging
    "dev", "dev2", "development", "staging", "stage", "stg", "test", "testing",
    "qa", "uat", "sandbox", "demo", "preview", "beta", "alpha", "canary",
    # Auth / identity
    "auth", "login", "sso", "oauth", "idp", "identity", "account", "accounts",
    "signup", "register", "password", "reset",
    # Admin / management
    "admin", "administrator", "manage", "management", "manager", "console",
    "control", "cp", "panel", "dashboard", "backstage", "internal",
    # Infrastructure
    "mail", "smtp", "imap", "pop", "email", "mx", "webmail",
    "vpn", "remote", "access", "gateway", "proxy",
    "cdn", "static", "assets", "images", "img", "media", "upload", "uploads",
    "files", "storage", "s3", "blob",
    # Services
    "mobile", "m", "ios", "android", "app1", "app2",
    "docs", "help", "support", "kb", "wiki", "faq", "forum",
    "status", "health", "ping", "monitor", "monitoring", "uptime",
    "metrics", "stats", "grafana", "kibana", "prometheus", "datadog",
    # Cloud / DevOps
    "ci", "cd", "jenkins", "gitlab", "github", "bitbucket",
    "docker", "registry", "k8s", "kubernetes", "rancher",
    "vault", "secrets", "config", "configs",
    # Networking
    "ns", "ns1", "ns2", "dns", "rdns", "ftp", "sftp", "ssh",
    "secure", "ssl", "tls",
    # Business
    "corp", "corporate", "hr", "legal", "finance", "billing",
    "pay", "payment", "payments", "checkout", "shop", "store", "commerce",
    "crm", "erp", "jira", "confluence",
    # Microservices / APIs
    "v1", "v2", "v3", "graphql", "rest", "grpc", "ws", "websocket",
    "service", "services", "micro", "backend", "bff",
    "data", "db", "database", "redis", "cache", "queue", "mq",
    # Analytics / BI
    "analytics", "bi", "reporting", "reports", "insights", "metabase",
    # Misc common
    "old", "new", "legacy", "archive", "backup", "bak",
    "external", "public", "private", "partner", "partners",
    "api-gateway", "apigw", "edge", "origin",
]

# Asynchronous DNS brute-forcer for fallback wordlist
async def _dns_brute(
    domain: str,
    prefixes: list,
    log: Callable,
    concurrency: int = 20,
) -> list:
    """
    Fix 6 (v3.4): Async concurrent DNS resolution for subdomain wordlist.
    Uses asyncio to resolve all prefixes concurrently (100 at a time)
    rather than sequential blocking calls — handles 200 prefixes in ~2s.
    """
    import asyncio as _aio
    valid = []
    sem   = _aio.Semaphore(max(1, int(concurrency)))

    async def resolve(prefix):
        fqdn = "{}.{}".format(prefix, domain)
        async with sem:
            try:
                proc = await _aio.create_subprocess_exec(
                    "python3", "-c",
                    "import socket; socket.getaddrinfo('{}', None)".format(fqdn),
                    stdout=_aio.subprocess.DEVNULL,
                    stderr=_aio.subprocess.DEVNULL,
                )
                try:
                    rc = await _aio.wait_for(proc.communicate(), timeout=3.0)
                    if proc.returncode == 0:
                        valid.append(fqdn)
                except _aio.TimeoutError:
                    proc.kill()
            except Exception:
                pass

    log("[Recon] DNS brute-force: {} prefixes concurrently".format(len(prefixes)))
    await _aio.gather(*[resolve(p) for p in prefixes])
    log("[Recon] DNS brute found {} live subdomains".format(len(valid)))
    return valid


async def enumerate_subdomains(
    domain: str,
    log: Callable,
    concurrency: int = 20,
) -> list:
    subs = set()

    if tool_available("subfinder"):
        log("[Recon] Running subfinder on {}".format(domain))
        out = await run_cmd([
            "subfinder", "-d", domain, "-silent",
            "-t", str(max(1, int(concurrency))),
        ], timeout=120)
        for line in out.strip().splitlines():
            line = line.strip()
            if line and "." in line:
                subs.add(line.lower())
        log("[Recon] subfinder found {} subdomains".format(len(subs)))
    else:
        log("[Recon] subfinder not installed — async DNS brute with {} prefixes".format(
            len(FALLBACK_SUBS)))
        # Fix 6: Use async concurrent DNS resolution instead of blind set-add
        brute_results = await _dns_brute(
            domain, FALLBACK_SUBS, log, concurrency=concurrency
        )
        subs.update(brute_results)

    # Always include the domain itself
    subs.add(domain)
    return sorted(subs)
    return sorted(subs)


# ── Phase 1b: Live Host Probing ───────────────────────────────────────────────

async def probe_live_hosts(
    subdomains: list[str],
    log: Callable,
    concurrency: int = 10,
) -> list[dict]:
    """
    Returns list of live hosts:
    {"url": "https://...", "status": 200, "title": "...", "tech": [...], "ip": "..."}
    """
    subdomains = [s for s in subdomains if scope_policy.validate_target(s, action="scan")[0]]
    live = []

    if tool_available("httpx"):
        log("[Recon] Running httpx on {} subdomains".format(len(subdomains)))
        input_data = "\n".join(subdomains).encode()
        proc = await asyncio.create_subprocess_exec(
            "httpx", "-silent", "-status-code", "-title",
            "-tech-detect", "-json", "-timeout", "8",
            "-threads", str(max(1, int(concurrency))),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=180
            )
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                try:
                    obj = json.loads(line)
                    live.append({
                        "url":    obj.get("url", ""),
                        "status": obj.get("status-code", 0),
                        "title":  obj.get("title", ""),
                        "tech":   obj.get("tech", []),
                        "ip":     obj.get("host", ""),
                    })
                except Exception:
                    pass
        except asyncio.TimeoutError:
            proc.kill()
    else:
        log("[Recon] httpx not installed — using fallback HTTP prober")
        await _fallback_probe(subdomains, live, log, concurrency=concurrency)

    log("[Recon] {} live hosts found".format(len(live)))
    return live


async def _fallback_probe(
    subdomains: list[str],
    live: list,
    log: Callable,
    concurrency: int = 10,
):
    """Pure-Python fallback when httpx binary isn't available."""
    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def probe_one(sub: str):
        async with sem:
            for scheme in ("https", "http"):
                url = "{}://{}".format(scheme, sub)
                try:
                    async with httpx.AsyncClient(
                        timeout=6, verify=False,
                        follow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (BugHunter)"}
                    ) as c:
                        r = await c.get(url)
                        title = ""
                        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                        if m:
                            title = m.group(1).strip()[:100]
                        live.append({
                            "url":    str(r.url),
                            "status": r.status_code,
                            "title":  title,
                            "tech":   _detect_tech(r),
                            "ip":     sub,
                        })
                        return
                except Exception:
                    pass

    await asyncio.gather(*[probe_one(s) for s in subdomains])


def _detect_tech(response) -> list[str]:
    tech = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    body    = response.text[:5000].lower()
    server  = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if "nginx"      in server.lower():   tech.append("Nginx")
    if "apache"     in server.lower():   tech.append("Apache")
    if "iis"        in server.lower():   tech.append("IIS")
    if "php"        in powered.lower():  tech.append("PHP")
    if "asp.net"    in powered.lower():  tech.append("ASP.NET")
    if "express"    in powered.lower():  tech.append("Express.js")
    if "wp-content" in body:             tech.append("WordPress")
    if "joomla"     in body:             tech.append("Joomla")
    if "drupal"     in body:             tech.append("Drupal")
    if "graphql"    in body:             tech.append("GraphQL")
    if "react"      in body:             tech.append("React")
    if "angular"    in body:             tech.append("Angular")
    if "laravel"    in body:             tech.append("Laravel")
    if "django"     in body:             tech.append("Django")
    if "spring"     in body:             tech.append("Spring")
    return tech


# ── Phase 1c: URL & Endpoint Discovery ───────────────────────────────────────

async def discover_urls(live_hosts: list[dict], log: Callable) -> list[str]:
    live_hosts = [h for h in live_hosts if scope_policy.validate_target(h.get("url", ""), action="scan")[0]]
    urls = set()
    base_urls = [h["url"] for h in live_hosts if h.get("status", 0) < 400][:20]

    # Try katana first
    if tool_available("katana") and base_urls:
        log("[Recon] Running katana crawler on {} hosts".format(len(base_urls)))
        out = await run_cmd(
            ["katana", "-u"] + base_urls +
            ["-silent", "-d", "3", "-jc", "-kf", "all", "-timeout", "10"],
            timeout=180
        )
        for line in out.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line)
        log("[Recon] katana found {} URLs".format(len(urls)))

    # Try waybackurls / gau
    for tool in ("gau", "waybackurls"):
        if tool_available(tool) and base_urls:
            log("[Recon] Running {} for historical URLs".format(tool))
            for base in base_urls[:5]:
                domain = urlparse(base).netloc
                out = await run_cmd([tool, domain], timeout=60)
                for line in out.strip().splitlines():
                    if line.startswith("http"):
                        urls.add(line.strip())

    # Fallback: crawl manually
    if not urls and base_urls:
        log("[Recon] No crawler available — using built-in spider")
        for base in base_urls[:5]:
            crawled = await _simple_crawl(base, depth=min(2, scope_policy.config.max_depth or 2))
            urls.update(crawled)

    log("[Recon] Total URLs discovered: {}".format(len(urls)))
    return list(urls)


async def _simple_crawl(base_url: str, depth: int = 2) -> set[str]:
    """Minimal HTML link crawler fallback."""
    ok, _ = scope_policy.validate_target(base_url, action="scan")
    if not ok:
        return set()
    found  = set()
    queue  = [(base_url, 0)]
    visited = set()
    base_domain = urlparse(base_url).netloc

    async with httpx.AsyncClient(
        timeout=8, verify=False, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter)"}
    ) as client:
        while queue:
            url, d = queue.pop(0)
            if url in visited or d > depth:
                continue
            visited.add(url)
            found.add(url)
            try:
                ok, _ = scope_policy.record_request(url, action="scan")
                if not ok:
                    continue
                r     = await client.get(url)
                links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
                for link in links[:50]:
                    abs_link = urljoin(url, link).split("#")[0]
                    if urlparse(abs_link).netloc == base_domain and scope_policy.validate_target(abs_link, action="scan")[0]:
                        if abs_link not in visited:
                            queue.append((abs_link, d + 1))
            except Exception:
                pass

    return found


# ── Phase 1c.5: Technology-aware Active Content Discovery ─────────────────────

GENERIC_CONTENT_PATHS = [
    "/.git/HEAD", "/.env", "/backup.zip", "/api/v1", "/api/v2",
    "/graphql", "/graphiql",
]
ADMIN_CONTENT_PATHS = [
    "/admin", "/administrator", "/manage", "/management", "/dashboard", "/portal",
]
API_DOC_CONTENT_PATHS = [
    "/swagger-ui.html", "/api-docs", "/openapi.json", "/redoc",
]

# Retained as public constants because the dashboard imports them.
COMMON_CONTENT_PATHS = sorted(set(
    GENERIC_CONTENT_PATHS + ADMIN_CONTENT_PATHS + API_DOC_CONTENT_PATHS
))
TECH_CONTENT_PATHS = {
    "WordPress": [
        "/wp-admin", "/wp-login.php", "/xmlrpc.php",
        "/wp-config.php.bak", "/wp-content/debug.log",
    ],
    "Spring Boot": [
        "/actuator", "/actuator/env", "/actuator/beans",
        "/actuator/mappings", "/h2-console",
    ],
    "Laravel": [
        "/telescope", "/.env", "/storage/logs/laravel.log", "/api/documentation",
    ],
    "Django": ["/admin/", "/django-admin/", "/static/admin/"],
    "Rails": ["/rails/info/properties", "/admin", "/console"],
}
BACKUP_EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".save", "~", ".zip", ".tar.gz", ".sql"]

_CONTENT_DISCOVERY_STATUS: dict[str, int] = {}


def _normalize_content_tech(tech: str) -> str:
    value = str(tech or "").lower()
    if "wordpress" in value:
        return "WordPress"
    if "spring" in value:
        return "Spring Boot"
    if "laravel" in value:
        return "Laravel"
    if "django" in value:
        return "Django"
    if "rails" in value or "ruby on rails" in value:
        return "Rails"
    return ""


def _content_paths_for_tech(tech_stack: list) -> list[str]:
    paths = set(COMMON_CONTENT_PATHS)
    for tech in tech_stack or []:
        normalized = _normalize_content_tech(str(tech))
        if normalized:
            paths.update(TECH_CONTENT_PATHS[normalized])
    return sorted(paths)


async def discover_content(
    live_hosts: list,
    tech_stack: list,
    log: Callable,
    concurrency: int = 6,
) -> list[str]:
    """Actively probe scoped, technology-aware paths and return existing URLs."""
    hosts = [
        host for host in (live_hosts or [])
        if isinstance(host, dict)
        and host.get("url")
        and scope_policy.validate_target(host["url"], action="scan")[0]
    ][:20]
    if not hosts:
        return []

    _CONTENT_DISCOVERY_STATUS.clear()
    discovered: set[str] = set()
    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def probe(client: httpx.AsyncClient, url: str):
        # Validate immediately before every request, then record it through the
        # central policy so rate and total-request caps are also enforced.
        allowed, _reason = scope_policy.validate_target(url, action="scan")
        if not allowed:
            return
        allowed, _reason = scope_policy.record_request(url, action="scan")
        if not allowed:
            return
        async with sem:
            try:
                response = await client.get(url, follow_redirects=False)
            except httpx.HTTPError:
                return
        if response.status_code in (200, 401, 403):
            discovered.add(url)
            _CONTENT_DISCOVERY_STATUS[url] = response.status_code

    async with httpx.AsyncClient(
        timeout=7,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter ContentDiscovery)"},
    ) as client:
        probe_urls = []
        for host in hosts:
            base_url = str(host["url"])
            parsed_base = urlparse(base_url)
            origin = "{}://{}".format(parsed_base.scheme, parsed_base.netloc)
            host_tech = list(tech_stack or []) + list(host.get("tech") or [])
            for path in _content_paths_for_tech(host_tech):
                url = urljoin(origin + "/", path.lstrip("/"))
                probe_urls.append(url)
        log("[Recon] Active content discovery probing {} scoped paths".format(
            len(probe_urls)
        ))
        batch_size = max(4, int(concurrency) * 4)
        for offset in range(0, len(probe_urls), batch_size):
            await asyncio.gather(*[
                probe(client, url)
                for url in probe_urls[offset:offset + batch_size]
            ])
            await asyncio.sleep(0)

    results = sorted(discovered)
    protected = sum(
        1 for url in results if _CONTENT_DISCOVERY_STATUS.get(url) in (401, 403)
    )
    log("[Recon] Active content discovery found {} path(s), {} protected".format(
        len(results), protected
    ))
    return results


# ── Phase 1d: JS File Analysis ────────────────────────────────────────────────

JS_SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})",  "API Key in JS"),
    (r"(?i)(secret|password|passwd|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Secret in JS"),
    (r"AKIA[0-9A-Z]{16}",                                                  "AWS Key in JS"),
    (r"(?i)firebase[A-Za-z]*\s*[:=]\s*['\"]([^'\"]+)['\"]",               "Firebase Config in JS"),
    (r"(?i)(endpoint|baseurl|base_url|api_url)\s*[:=]\s*['\"]([^'\"]+)['\"]", "API Endpoint in JS"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",        "Hardcoded JWT in JS"),
    (r"(?i)(internal|private|admin)\.(api|service|endpoint)",              "Internal Service in JS"),
    (r"sourceMappingURL=([^\s]+\.map)",                                    "Source Map Reference"),
    (r"(?i)/graphql",                                                       "GraphQL Endpoint in JS"),
    (r"(?i)(debug|test|dev)[Mm]ode\s*[:=]\s*true",                        "Debug Mode Enabled"),
]

async def analyze_js_files(urls: list, log: Callable) -> list:
    """
    Download JS files and run two analysis passes:
      Pass 1 — 10 regex patterns (secrets, endpoints, config)
      Pass 2 — semgrep DOM-XSS / prototype pollution rules (if installed)
    """
    urls = scope_policy.filter_urls(list(urls or []), action="scan")
    js_urls  = [u for u in urls if u.endswith(".js") and ".min.js" not in u][:30]
    findings = []

    log("[Recon] Analyzing {} JS files (regex + semgrep)".format(len(js_urls)))

    semgrep_available = shutil.which("semgrep") is not None
    if not semgrep_available:
        log("[Recon] semgrep not found — regex-only JS analysis (install: pip install semgrep)")

    # Download all JS files first
    js_contents = {}   # url → content
    async with httpx.AsyncClient(
        timeout=12, verify=False, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter)"}
    ) as client:
        for js_url in js_urls:
            try:
                ok, _ = scope_policy.record_request(js_url, action="scan")
                if not ok:
                    continue
                r = await client.get(js_url)
                if r.status_code != 200:
                    continue
                js_contents[js_url] = r.text

                # ── Pass 1: Regex patterns ────────────────────────────────
                for pattern, label in JS_SECRET_PATTERNS:
                    for match in re.findall(pattern, r.text):
                        evidence = match if isinstance(match, str) else match[0]
                        findings.append({
                            "type":     label,
                            "file":     js_url,
                            "evidence": evidence[:200],
                            "source":   "regex",
                        })

                # Source map check
                map_url = js_url + ".map"
                try:
                    mr = await client.head(map_url)
                    if mr.status_code == 200:
                        findings.append({
                            "type":     "Source Map Exposed",
                            "file":     map_url,
                            "evidence": map_url,
                            "source":   "regex",
                        })
                except Exception:
                    pass
            except Exception:
                pass

    # ── Pass 2: Semgrep DOM-XSS / prototype pollution ─────────────────────────
    if semgrep_available and js_contents:
        semgrep_findings = await _run_semgrep_on_js(js_contents, log)
        findings.extend(semgrep_findings)

    log("[Recon] JS analysis complete: {} findings (regex={}, semgrep={})".format(
        len(findings),
        sum(1 for f in findings if f.get("source") == "regex"),
        sum(1 for f in findings if f.get("source") == "semgrep"),
    ))
    return findings


async def _run_semgrep_on_js(js_contents: dict, log: Callable) -> list:
    """
    v3.4 Fix 2: Syntax-aware JS chunking for semgrep.

    PROBLEM with raw byte/file-count chunking:
      Splitting a single large JS file mid-line destroys the AST.
      Semgrep silently fails to parse broken JS, missing XSS/pollution flows.

    FIX: We chunk by WHOLE FILES, not by byte offset within a file.
      - Each chunk contains complete, syntactically valid JS files.
      - If a single file exceeds the threshold alone, it gets its own chunk
        with an elevated --max-memory limit and longer timeout.
      - Timeouts → PARTIAL_COVERAGE warning, not silent drop.
    """
    SEMGREP_CHUNK_THRESHOLD_MB = 5
    SEMGREP_MAX_MEMORY_MB      = 512
    SEMGREP_TIMEOUT_SECS       = 60
    SEMGREP_LARGE_FILE_MB      = 2       # single file gets its own chunk + extra memory

    findings      = []
    coverage_gaps = []

    total_bytes = sum(len(c.encode("utf-8", errors="ignore"))
                      for c in js_contents.values())
    total_mb    = total_bytes / (1024 * 1024)

    log("[Recon] semgrep: {} JS files, {:.1f} MB total".format(
        len(js_contents), total_mb))

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_map  = {}
            file_sizes = {}   # path → size in MB
            for js_url, content in js_contents.items():
                safe_name = re.sub(r'[^\w.]', '_', js_url.split("/")[-1])[:60] or "file.js"
                temp_path = os.path.join(tmpdir, safe_name)
                try:
                    with open(temp_path, "w", encoding="utf-8", errors="ignore") as fh:
                        fh.write(content)
                    file_map[temp_path]   = js_url
                    file_sizes[temp_path] = len(content.encode("utf-8", errors="ignore")) / (1024*1024)
                except Exception as we:
                    log("[Recon] semgrep: write error {}: {}".format(safe_name, we))

            if not file_map:
                return []

            # Fix 2: Build whole-file chunks — never split a file across batches
            # Group files into chunks where each chunk stays under threshold
            chunks         = []
            current_chunk  = []
            current_size   = 0.0

            for path, size_mb in file_sizes.items():
                if size_mb >= SEMGREP_LARGE_FILE_MB:
                    # Large file gets its own chunk to avoid polluting others
                    if current_chunk:
                        chunks.append(current_chunk)
                    chunks.append([path])   # solo chunk
                    current_chunk = []
                    current_size  = 0.0
                elif current_size + size_mb > SEMGREP_CHUNK_THRESHOLD_MB:
                    if current_chunk:
                        chunks.append(current_chunk)
                    current_chunk = [path]
                    current_size  = size_mb
                else:
                    current_chunk.append(path)
                    current_size += size_mb

            if current_chunk:
                chunks.append(current_chunk)

            log("[Recon] semgrep: {} whole-file chunks (no mid-file splits)".format(
                len(chunks)))

            for chunk_idx, chunk_paths in enumerate(chunks):
                is_large_solo  = len(chunk_paths) == 1 and \
                                  file_sizes.get(chunk_paths[0], 0) >= SEMGREP_LARGE_FILE_MB
                mem_limit      = str(SEMGREP_MAX_MEMORY_MB * 2) if is_large_solo \
                                 else str(SEMGREP_MAX_MEMORY_MB)
                timeout_secs   = SEMGREP_TIMEOUT_SECS * 2 if is_large_solo \
                                 else SEMGREP_TIMEOUT_SECS

                log("[Recon] semgrep chunk {}/{}: {} file(s) (mem={}MB, timeout={}s)".format(
                    chunk_idx + 1, len(chunks), len(chunk_paths),
                    mem_limit, timeout_secs))

                cmd = [
                    "semgrep",
                    "--config", "p/javascript",
                    "--config", "p/xss",
                    "--json",
                    "--no-git-ignore",
                    "--quiet",
                    "--max-memory", mem_limit,
                ] + chunk_paths   # whole files — AST always intact

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=timeout_secs)
                    except asyncio.TimeoutError:
                        try:
                            proc.kill(); await proc.wait()
                        except Exception:
                            pass
                        gap_files = [file_map.get(p, p) for p in chunk_paths]
                        log("[Recon] ⚠ PARTIAL_COVERAGE chunk {}: timeout {}s — {} file(s): {}".format(
                            chunk_idx + 1, timeout_secs, len(gap_files),
                            [f.split("/")[-1] for f in gap_files[:3]]))
                        coverage_gaps.append({
                            "chunk": chunk_idx + 1,
                            "files": gap_files,
                            "reason": "timeout_{}s".format(timeout_secs),
                        })
                        continue

                    if not stdout:
                        continue

                    try:
                        output = json.loads(stdout.decode("utf-8", errors="ignore"))
                    except json.JSONDecodeError:
                        continue

                    for result in output.get("results", []):
                        rule_id  = result.get("check_id", "")
                        path     = result.get("path", "")
                        message  = result.get("extra", {}).get("message", "")
                        severity = result.get("extra", {}).get("severity", "WARNING")
                        lines    = result.get("extra", {}).get("lines", "")
                        line_no  = result.get("start", {}).get("line", 0)
                        orig_url = file_map.get(path, path)
                        sev_map  = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                        our_sev  = sev_map.get(severity.upper(), "MEDIUM")
                        if any(kw in rule_id.lower() for kw in
                               ["eval", "innerhtml", "xss", "prototype",
                                "pollution", "document.write", "settimeout"]):
                            our_sev = "HIGH"
                        findings.append({
                            "type":     "Semgrep: {}".format(rule_id.split(".")[-1]),
                            "file":     orig_url,
                            "evidence": "Line {}: {}".format(line_no, lines[:200]),
                            "source":   "semgrep",
                            "rule_id":  rule_id,
                            "severity": our_sev,
                            "message":  message[:300],
                        })

                except FileNotFoundError:
                    log("[Recon] semgrep binary gone mid-scan"); break
                except Exception as chunk_err:
                    log("[Recon] semgrep chunk {} error: {}".format(chunk_idx+1, chunk_err))
                    continue

    except Exception as outer_err:
        log("[Recon] semgrep outer error: {}".format(outer_err))

    log("[Recon] semgrep: {} findings | {} chunks | {} coverage gaps".format(
        len(findings), len(chunks) if 'chunks' in dir() else 0, len(coverage_gaps)))
    return findings

    log("[Recon] semgrep complete: {} finding(s) across {} chunk(s)".format(
        len(findings), len(chunks) if 'chunks' in dir() else 1))
    if coverage_gaps:
        log("[Recon] ⚠ PARTIAL_COVERAGE: {}/{} chunks had timeouts — JS analysis incomplete".format(
            len(coverage_gaps), len(chunks) if 'chunks' in dir() else 1))
    return findings


# ── Structural URL clustering (replaces naive hard cap) ───────────────────────

def _path_template(url: str) -> str:
    """
    Convert a URL into a structural template by replacing variable path
    segments with typed placeholders.
    e.g. /api/users/42/orders/9  →  /api/users/{id}/orders/{id}
         /view/item/abc123def456  →  /view/item/{token}
         /u/550e8400-e29b-41d4    →  /u/{uuid}
    Includes scheme+host so cross-subdomain paths don't collide.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    segments    = parsed.path.split("/")
    templated   = []

    for seg in segments:
        if not seg:
            templated.append(seg)
            continue
        # Pure integer ID
        if re.match(r'^\d+$', seg):
            templated.append("{id}")
        # UUID v1-v5
        elif re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            seg, re.IGNORECASE
        ):
            templated.append("{uuid}")
        # Long hex hash (MD5/SHA)
        elif re.match(r'^[0-9a-f]{16,}$', seg, re.IGNORECASE):
            templated.append("{hash}")
        # Long opaque token / slug (alphanumeric ≥ 16 chars, likely a token)
        elif re.match(r'^[A-Za-z0-9_\-]{16,}$', seg) and not seg.isalpha():
            templated.append("{token}")
        else:
            templated.append(seg)

    template_path = "/".join(templated)
    return "{}://{}{}".format(parsed.scheme, parsed.netloc, template_path)


def cluster_urls(
    urls:            list,
    max_variants:    int  = 3,
    max_per_status:  int  = 2,
    status_map:      dict = None,
) -> list:
    """
    v3.3: Cluster URLs by structural path template.

    Without status_map: keep max_variants examples per template (original).
    With status_map (url → status_code): keep max_per_status examples per
    (template, status_code) pair — preserves differential responses needed
    for IDOR testing (e.g. one 200 Admin + one 403 User for same template).

    status_map is populated by probe_live_hosts() or Phase 2 fetch results.
    """
    from collections import OrderedDict, defaultdict

    if status_map:
        # Key: (template, status_code) → keeps differential responses
        template_status_map = defaultdict(list)  # (tmpl, status) → [urls]
        for url in urls:
            try:
                tmpl   = _path_template(url)
                status = status_map.get(url, 0)
                key    = (tmpl, status)
            except Exception:
                key = (url, 0)
            if len(template_status_map[key]) < max_per_status:
                template_status_map[key].append(url)
        clustered = []
        for variants in template_status_map.values():
            clustered.extend(variants)
        return clustered
    else:
        # Original behaviour — template only
        template_map = OrderedDict()
        for url in urls:
            try:
                tmpl = _path_template(url)
            except Exception:
                tmpl = url
            if tmpl not in template_map:
                template_map[tmpl] = []
            if len(template_map[tmpl]) < max_variants:
                template_map[tmpl].append(url)
        clustered = []
        for variants in template_map.values():
            clustered.extend(variants)
        return clustered


# ── Master recon runner ────────────────────────────────────────────────────────

async def run_full_recon(
    target: str,
    log: Callable,
    adaptive_plan: dict | None = None,
) -> dict:
    """
    Run the full recon pipeline.
    Returns a dict with all discovered assets.
    """
    ok, reason = scope_policy.validate_target(target, action="scan")
    if not ok:
        log("[Recon] Blocked by ScopePolicy: {}".format(reason))
        return {
            "domain": target,
            "subdomains": [],
            "live_hosts": [],
            "urls": [],
            "js_findings": [],
            "stats": {"subdomains": 0, "live_hosts": 0, "urls_raw": 0,
                      "urls_clustered": 0, "js_findings": 0},
        }
    plan = adaptive_plan or {}
    scan_level = str(plan.get("level", "BALANCED")).upper()
    max_urls = max(10, int(plan.get("max_urls", 200) or 200))
    concurrency = max(1, int(plan.get("concurrency", 4) or 4))
    log("[Recon] ━━━ Phase 1: {} discovery starting on {} ━━━".format(
        scan_level, target
    ))
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    # 1a. Subdomains
    log("[Recon] 1a — Subdomain enumeration")
    if scan_level == "LIGHT":
        subdomains = [domain]
        log("[Recon] LIGHT plan: broad subdomain enumeration skipped")
    else:
        subdomains = await enumerate_subdomains(
            domain, log, concurrency=concurrency
        )

    # 1b. Live hosts
    log("[Recon] 1b — Probing live hosts")
    live_hosts = await probe_live_hosts(
        subdomains, log, concurrency=concurrency
    )

    # 1c. URL discovery
    log("[Recon] 1c — URL/endpoint discovery")
    raw_urls = await discover_urls(live_hosts, log)
    raw_urls = raw_urls[:max_urls * 3]

    # ── Replace naive [:500] cap with structural clustering ───────────────────
    raw_urls = scope_policy.filter_urls(raw_urls, action="scan")
    urls = cluster_urls(raw_urls, max_variants=3)
    log("[Recon] URL clustering: {} raw → {} clustered (3 variants/template)".format(
        len(raw_urls), len(urls)
    ))

    # 1c.5. Technology-aware active content discovery
    log("[Recon] 1c.5 — Technology-aware active content discovery")
    tech_stack = sorted({
        str(tech)
        for host in live_hosts
        for tech in (host.get("tech") or [])
        if str(tech).strip()
    })
    content_discovery = (
        []
        if scan_level == "LIGHT"
        else await discover_content(
            live_hosts, tech_stack, log, concurrency=concurrency
        )
    )
    content_urls = list(content_discovery)
    if content_urls:
        urls = cluster_urls(scope_policy.filter_urls(urls + content_urls, action="scan"), max_variants=3)
        log("[Recon] Content discovery merged {} URL(s); clustered total now {}".format(
            len(content_urls), len(urls)))

    # 1d. JS analysis
    log("[Recon] 1d — JS file analysis")
    js_findings = await analyze_js_files(urls[:max_urls], log)

    # 1e. Runtime JavaScript endpoint extraction
    js_urls = [
        url for url in urls
        if urlparse(url).path.lower().endswith(".js")
        and not urlparse(url).path.lower().endswith(".min.js")
    ]
    base_url = (
        live_hosts[0].get("url", target)
        if live_hosts else target
    )
    async with httpx.AsyncClient(
        timeout=12,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter JS Endpoint Extractor)"},
    ) as client:
        js_endpoints = await extract_js_endpoints(js_urls, base_url, client)
    if js_endpoints:
        urls = cluster_urls(
            scope_policy.filter_urls(urls + js_endpoints, action="scan"),
            max_variants=3,
        )
    urls = urls[:max_urls]
    log("JS endpoint extraction: found {} additional API endpoints".format(
        len(js_endpoints)
    ))

    result = {
        "domain":      domain,
        "subdomains":  subdomains,
        "live_hosts":  live_hosts,
        "tech_stack":  tech_stack,
        "urls":        urls,          # clustered — no arbitrary cap
        "content_discovery": content_discovery,
        "js_endpoints": js_endpoints,
        "js_findings": js_findings,
        "stats": {
            "subdomains":    len(subdomains),
            "live_hosts":    len(live_hosts),
            "urls_raw":      len(raw_urls),
            "urls_clustered":len(urls),
            "content_discovery": len(content_discovery),
            "content_401_403": len([
                url for url in content_discovery
                if _CONTENT_DISCOVERY_STATUS.get(url) in (401, 403)
            ]),
            "js_endpoints":  len(js_endpoints),
            "js_findings":   len(js_findings),
        }
    }

    log("[Recon] ━━━ Phase 1 complete: {} hosts | {} clustered URLs | {} content paths | {} JS findings ━━━".format(
        len(live_hosts), len(urls), len(content_discovery), len(js_findings)
    ))
    return result
