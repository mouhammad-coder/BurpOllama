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


def _is_local_target(target: str) -> bool:
    """Returns True if target is localhost, IP, or local network."""
    value = str(target or "").strip()
    parsed = urlparse(value if "://" in value else "http://" + value)
    host = parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]
    return bool(
        host == "localhost"
        or host.startswith("127.")
        or host.startswith("192.168.")
        or host.startswith("10.")
        or host.startswith("172.")
        or re.match(r"^\d+\.\d+\.\d+\.\d+$", host)
    )


def _target_url(target: str) -> str:
    value = str(target or "").strip()
    return value if "://" in value else "http://" + value


def _local_connection_candidates(target: str) -> list[str]:
    """Return loopback transport aliases while preserving the target port/path."""
    target_url = _target_url(target)
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if not (
        host == "localhost"
        or host == "0.0.0.0"
        or host.startswith("127.")
    ):
        return [target_url]
    port = ":{}".format(parsed.port) if parsed.port else ""
    suffix = parsed.path or ""
    if parsed.query:
        suffix += "?" + parsed.query
    return [
        "http://127.0.0.1{}{}".format(port, suffix),
        "http://localhost{}{}".format(port, suffix),
        "http://0.0.0.0{}{}".format(port, suffix),
    ]


def _canonicalize_local_url(url: str, canonical_base_url: str) -> str:
    """Map a loopback transport URL back to the user-authorized hostname."""
    parsed = urlparse(url)
    canonical = urlparse(canonical_base_url)
    if not parsed.netloc or not canonical.netloc:
        return url
    if (
        (parsed.hostname or "").lower()
        in {"localhost", "127.0.0.1", "0.0.0.0"}
    ):
        return parsed._replace(
            scheme=canonical.scheme,
            netloc=canonical.netloc,
        ).geturl()
    return url


async def probe_target_connection(target: str):
    """Probe a target, trying equivalent loopback aliases when appropriate."""
    target_url = _target_url(target)
    candidates = _local_connection_candidates(target_url)
    errors = []
    timeout = (
        httpx.Timeout(15.0, connect=10.0)
        if _is_local_target(target_url)
        else httpx.Timeout(15.0, connect=10.0)
    )
    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        for candidate in candidates:
            try:
                response = await client.get(candidate)
                if response is not None:
                    return response, candidate, None
            except Exception as exc:
                errors.append("{}: {}".format(candidate, exc))
    return None, None, "; ".join(errors) or "All connection attempts failed"


def _extract_title(body: str) -> str:
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        str(body or ""),
        re.IGNORECASE | re.DOTALL,
    )
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else "Unknown"


async def _recon_log(log: Callable, message: str, level: str = "info"):
    try:
        result = log(message, level)
    except TypeError:
        result = log(message)
    if asyncio.iscoroutine(result):
        await result


def semgrep_available() -> bool:
    """Semgrep is optional because installation can fail on some Kali releases."""
    try:
        return shutil.which("semgrep") is not None
    except Exception:
        return False

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

    await _recon_log(log, "[Recon] DNS brute-force: {} prefixes concurrently".format(len(prefixes)))
    await _aio.gather(*[resolve(p) for p in prefixes])
    await _recon_log(log, "[Recon] DNS brute found {} live subdomains".format(len(valid)))
    return valid


async def enumerate_subdomains(
    domain: str,
    log: Callable,
    concurrency: int = 20,
) -> list:
    subs = set()

    if tool_available("subfinder"):
        await _recon_log(log, "[Recon] Running subfinder on {}".format(domain))
        out = await run_cmd([
            "subfinder", "-d", domain, "-silent",
            "-t", str(max(1, int(concurrency))),
        ], timeout=120)
        for line in out.strip().splitlines():
            line = line.strip()
            if line and "." in line:
                subs.add(line.lower())
        await _recon_log(log, "[Recon] subfinder found {} subdomains".format(len(subs)))
    else:
        await _recon_log(log, "[Recon] subfinder not installed — async DNS brute with {} prefixes".format(
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
        await _recon_log(log, "[Recon] Running httpx on {} subdomains".format(len(subdomains)))
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
        await _recon_log(log, "[Recon] httpx not installed — using fallback HTTP prober")
        await _fallback_probe(subdomains, live, log, concurrency=concurrency)

    await _recon_log(log, "[Recon] {} live hosts found".format(len(live)))
    return live


async def probe_local_target(target: str, log: Callable) -> list[dict]:
    """Probe one localhost/IP URL without converting it into a domain name."""
    target_url = _target_url(target)
    direct_host = {
        "url": target_url,
        "status": 200,
        "title": "Local Target",
        "tech": [],
        "ip": urlparse(target_url).hostname or "",
    }
    response, method_url, error = await probe_target_connection(target_url)
    if response is not None:
        await _recon_log(
            log,
            "[Recon] Local probe: {} via {} → HTTP {}".format(
                target_url, method_url, response.status_code
            ),
        )
        return [{
            "url": target_url,
            "status": response.status_code,
            "title": _extract_title(response.text),
            "tech": _detect_tech(response),
            "ip": urlparse(target_url).hostname or "",
        }]
    await _recon_log(log, "[Recon] Local target probe failed: {}".format(error))
    return [direct_host]


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

async def discover_urls(
    live_hosts: list[dict],
    log: Callable,
    max_urls: int = 200,
) -> list[str]:
    live_hosts = [h for h in live_hosts if scope_policy.validate_target(h.get("url", ""), action="scan")[0]]
    urls = set()
    base_urls = [h["url"] for h in live_hosts if h.get("status", 0) < 400][:20]

    # Try katana first
    if tool_available("katana") and base_urls:
        await _recon_log(log, "[Recon] Running katana crawler on {} hosts".format(len(base_urls)))
        out = await run_cmd(
            ["katana", "-u"] + base_urls +
            ["-silent", "-d", "3", "-jc", "-kf", "all", "-timeout", "10"],
            timeout=180
        )
        for line in out.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line)
        await _recon_log(log, "[Recon] katana found {} URLs".format(len(urls)))

    # Try waybackurls / gau
    for tool in ("gau", "waybackurls"):
        if tool_available(tool) and base_urls:
            await _recon_log(log, "[Recon] Running {} for historical URLs".format(tool))
            for base in base_urls[:5]:
                domain = urlparse(base).netloc
                out = await run_cmd([tool, domain], timeout=60)
                for line in out.strip().splitlines():
                    if line.startswith("http"):
                        urls.add(line.strip())

    # Fallback: crawl manually
    if not urls and base_urls:
        await _recon_log(log, "[Recon] No crawler available — using built-in spider")
        for base in base_urls[:5]:
            remaining = max(0, int(max_urls) - len(urls))
            if remaining <= 0:
                break
            crawled = await _simple_crawl(
                base,
                depth=min(2, scope_policy.config.max_depth or 2),
                max_urls=remaining,
            )
            urls.update(crawled)

    await _recon_log(log, "[Recon] Total URLs discovered: {}".format(len(urls)))
    return list(urls)


async def _python_crawl(
    base_url: str,
    client: httpx.AsyncClient,
    max_depth: int = 3,
    canonical_base_url: str | None = None,
    max_urls: int = 200,
) -> list[str]:
    """Primary local crawler using only httpx and regular expressions."""
    canonical_base = canonical_base_url or base_url
    request_origin = urlparse(base_url)
    canonical_origin = urlparse(canonical_base)
    allowed_hosts = {
        (request_origin.hostname or "").lower(),
        (canonical_origin.hostname or "").lower(),
    }
    if _is_local_target(canonical_base):
        allowed_hosts.update({"localhost", "127.0.0.1", "0.0.0.0"})

    visited = set()
    to_visit = [base_url]
    found = []
    for _depth in range(max(1, int(max_depth))):
        next_visit = []
        for url in to_visit:
            if len(found) >= max(1, int(max_urls)):
                break
            if url in visited:
                continue
            visited.add(url)
            try:
                canonical_request = _canonicalize_local_url(
                    url, canonical_base
                )
                allowed, _reason = scope_policy.record_request(
                    canonical_request, action="scan"
                )
                if not allowed:
                    continue
                response = await client.get(url, timeout=8)
                if response is None:
                    continue
                found.append(canonical_request)
                links = re.findall(
                    r"""(?i)\bhref\s*=\s*["']([^"']+)["']""",
                    response.text or "",
                )
                links += re.findall(
                    r"""(?i)\bsrc\s*=\s*["']([^"']+)["']""",
                    response.text or "",
                )
                links += re.findall(
                    r"""(?i)\baction\s*=\s*["']([^"']+)["']""",
                    response.text or "",
                )
                for link in links:
                    if link.lower().startswith((
                        "javascript:", "mailto:", "tel:", "data:", "blob:",
                    )):
                        continue
                    full = urljoin(str(response.url), link).split("#", 1)[0]
                    parsed_link = urlparse(full)
                    if (
                        parsed_link.scheme in {"http", "https"}
                        and (parsed_link.hostname or "").lower() in allowed_hosts
                        and full not in visited
                        and len(found) + len(next_visit) < max(1, int(max_urls))
                    ):
                        next_visit.append(full)
            except Exception:
                pass
        to_visit = list(dict.fromkeys(next_visit))
    return list(dict.fromkeys(found))


JUICE_SHOP_PATHS = [
    "/rest/products/search?q=test",
    "/api/Users",
    "/rest/user/login",
    "/rest/BasketItems",
    "/api/Challenges",
    "/rest/admin/application-configuration",
    "/ftp/",
    "/socket.io/",
    "/assets/public/",
    "/#/login",
    "/#/search",
]


async def discover_local_urls(
    target: str,
    log: Callable,
    reachable_url: str | None = None,
    max_urls: int = 200,
) -> list[str]:
    """Crawl local targets in Python first, then optionally supplement with Katana."""
    target_url = _target_url(target)
    urls = {target_url}
    method_url = reachable_url
    timeout = httpx.Timeout(15.0, connect=10.0)
    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        if not method_url:
            for candidate in _local_connection_candidates(target_url):
                try:
                    response = await client.get(candidate, timeout=5)
                    if response is not None and response.status_code < 500:
                        method_url = candidate
                        break
                except Exception:
                    continue

        if method_url:
            crawled = await _python_crawl(
                method_url,
                client,
                max_depth=3,
                canonical_base_url=target_url,
                max_urls=max_urls,
            )
            urls.update(crawled)
            await _recon_log(
                log,
                "[Recon] Python crawler found {} local URL(s)".format(
                    len(crawled)
                ),
            )

            for path in JUICE_SHOP_PATHS:
                request_url = urljoin(method_url.rstrip("/") + "/", path.lstrip("/"))
                canonical_url = urljoin(
                    target_url.rstrip("/") + "/", path.lstrip("/")
                )
                try:
                    response = await client.get(request_url, timeout=5)
                    if response is not None and response.status_code < 500:
                        urls.add(canonical_url)
                        await _recon_log(
                            log,
                            "[Recon] Local path: {} → {}".format(
                                path, response.status_code
                            ),
                        )
                except Exception:
                    pass

            # Katana is supplemental only, and only runs after a successful
            # Python reachability check.
            if tool_available("katana"):
                await _recon_log(
                    log,
                    "[Recon] Running katana on reachable local URL {}".format(
                        method_url
                    ),
                )
                out = await run_cmd(
                    ["katana", "-u", method_url, "-d", "3", "-silent", "-jc"],
                    timeout=180,
                )
                for line in out.splitlines():
                    candidate = line.strip()
                    if candidate.startswith(("http://", "https://")):
                        urls.add(
                            _canonicalize_local_url(candidate, target_url)
                        )
        else:
            await _recon_log(
                log,
                "[Recon] Local URL is unreachable — skipping katana and continuing",
            )

    return list(dict.fromkeys(urls))


async def _simple_crawl(
    base_url: str,
    depth: int = 3,
    max_urls: int = 200,
) -> set[str]:
    """Crawl href, src, and form action attributes on the same origin."""
    ok, _ = scope_policy.validate_target(base_url, action="scan")
    if not ok:
        return set()
    found = {base_url}
    queue = [(base_url, 0)]
    visited = set()
    base_origin = urlparse(base_url).netloc.lower()

    async with httpx.AsyncClient(
        timeout=8, verify=False, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter)"}
    ) as client:
        while queue:
            if len(found) >= max(1, int(max_urls)):
                break
            url, d = queue.pop(0)
            if url in visited or d > depth:
                continue
            visited.add(url)
            found.add(url)
            try:
                ok, _ = scope_policy.record_request(url, action="scan")
                if not ok:
                    continue
                response = await client.get(url)
                if response is None:
                    continue
                links = re.findall(
                    r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"'#]+)["']""",
                    response.text or "",
                )
                for link in links[:300]:
                    if len(found) >= max(1, int(max_urls)):
                        break
                    if link.lower().startswith((
                        "javascript:", "mailto:", "tel:", "data:", "blob:",
                    )):
                        continue
                    absolute = urljoin(str(response.url), link).split("#", 1)[0]
                    parsed = urlparse(absolute)
                    if (
                        parsed.scheme in {"http", "https"}
                        and parsed.netloc.lower() == base_origin
                        and scope_policy.validate_target(absolute, action="scan")[0]
                    ):
                        found.add(absolute)
                        if (
                            absolute not in visited
                            and d < depth
                            and len(found) + len(queue) < max(1, int(max_urls))
                        ):
                            queue.append((absolute, d + 1))
            except Exception:
                pass

    return found


# ── Phase 1c.5: Technology-aware Active Content Discovery ─────────────────────

GENERIC_CONTENT_PATHS = [
    "/.git/HEAD", "/.env", "/backup.zip", "/api", "/api/v1", "/api/v2",
    "/graphql", "/graphiql", "/robots.txt",
]

COMMON_PATHS = [
    "/admin", "/administrator", "/admin/login",
    "/api", "/api/v1", "/api/v2",
    "/graphql", "/graphiql", "/api/graphql",
    "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/.env", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml",
    "/login", "/signin", "/signup", "/register",
    "/dashboard", "/account",
    "/upload", "/backup.zip",
    "/health", "/metrics",
    "/actuator/env", "/wp-admin", "/wp-login.php", "/server-status",
]
FULL_COMMON_PATHS = list(dict.fromkeys(COMMON_PATHS + [
    "/api/v3", "/swagger",
    "/logout", "/profile", "/password/reset", "/forgot-password",
    "/uploads", "/files", "/backup", "/backup.sql",
    "/config", "/settings", "/status",
    "/actuator", "/actuator/env", "/actuator/beans",
    "/console", "/h2-console",
    "/phpinfo.php", "/info.php",
    "/server-status", "/server-info",
    "/wp-admin", "/wp-login.php",
    "/rest", "/rest/user", "/rest/products",
    "/socket.io/", "/ftp/",
]))
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


async def _probe_common_paths(
    base_url: str,
    client: httpx.AsyncClient,
    log: Callable,
    paths: list[str] | None = None,
) -> list[str]:
    found = []
    origin = base_url.rstrip("/")
    selected_paths = list(dict.fromkeys(paths or COMMON_PATHS))
    sem = asyncio.Semaphore(15)

    async def probe(path: str):
        url = origin + path
        allowed, _reason = scope_policy.record_request(url, action="scan")
        if not allowed:
            return
        try:
            async with sem:
                response = await client.get(
                    url, timeout=3, follow_redirects=False
                )
            if response is None:
                return
            if response.status_code in (200, 201, 301, 302, 401, 403):
                found.append(url)
                _CONTENT_DISCOVERY_STATUS[url] = response.status_code
                await _recon_log(
                    log,
                    "[Recon] Found: {} → {}".format(path, response.status_code),
                )
        except Exception:
            pass

    await asyncio.gather(*(probe(path) for path in selected_paths))
    return found


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


def _content_paths_for_tech(
    tech_stack: list,
    include_full: bool = False,
) -> list[str]:
    paths = set(COMMON_CONTENT_PATHS)
    if include_full:
        paths.update(FULL_COMMON_PATHS)
        for technology_paths in TECH_CONTENT_PATHS.values():
            paths.update(technology_paths)
    for tech in tech_stack or []:
        normalized = _normalize_content_tech(str(tech))
        if normalized:
            paths.update(TECH_CONTENT_PATHS[normalized])
    if include_full:
        backup_candidates = [
            "/.env", "/.git/HEAD", "/config", "/settings", "/backup",
            "/backup.sql", "/api", "/api/v1", "/admin", "/administrator",
            "/login", "/dashboard", "/openapi.json", "/swagger-ui.html",
            "/wp-config.php", "/wp-login.php", "/server-status",
            "/actuator/env", "/h2-console", "/phpinfo.php",
        ]
        for path in backup_candidates:
            for extension in BACKUP_EXTENSIONS:
                paths.add(path + extension)
    return sorted(paths)


async def discover_content(
    live_hosts: list,
    tech_stack: list,
    log: Callable,
    concurrency: int = 6,
    max_probes: int | None = None,
    excluded_paths: set[str] | None = None,
    include_full_paths: bool = False,
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
        timeout=httpx.Timeout(3.0),
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (BugHunter ContentDiscovery)"},
    ) as client:
        probe_urls = []
        for host in hosts:
            base_url = str(host["url"])
            parsed_base = urlparse(base_url)
            origin = "{}://{}".format(parsed_base.scheme, parsed_base.netloc)
            host_tech = list(tech_stack or []) + list(host.get("tech") or [])
            for path in _content_paths_for_tech(
                host_tech, include_full=include_full_paths
            ):
                if path in (excluded_paths or set()):
                    continue
                url = urljoin(origin + "/", path.lstrip("/"))
                probe_urls.append(url)
        probe_urls = list(dict.fromkeys(probe_urls))
        if max_probes is not None:
            probe_urls = probe_urls[:max(0, int(max_probes))]
        await _recon_log(log, "[Recon] Active content discovery probing {} scoped paths".format(
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
    await _recon_log(log, "[Recon] Active content discovery found {} path(s), {} protected".format(
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
    (r"(?i)\bwss?://[^\s'\"`]+",                                          "WebSocket Endpoint"),
    (r"(?i)new\s+WebSocket\s*\(\s*['\"]([^'\"]+)",                       "WebSocket Endpoint"),
]

async def analyze_js_files(
    urls: list,
    log: Callable,
    return_contents: bool = False,
):
    """
    Download JS files and run two analysis passes:
      Pass 1 — 10 regex patterns (secrets, endpoints, config)
      Pass 2 — semgrep DOM-XSS / prototype pollution rules (if installed)
    """
    urls = scope_policy.filter_urls(list(urls or []), action="scan")
    js_urls  = [u for u in urls if u.endswith(".js") and ".min.js" not in u][:30]
    findings = []

    await _recon_log(log, "[Recon] Analyzing {} JS files (regex + semgrep)".format(len(js_urls)))

    has_semgrep = semgrep_available()
    if not has_semgrep:
        await _recon_log(log, "[Recon] semgrep not found — regex-only JS analysis (install: pip install semgrep)")

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
    if has_semgrep and js_contents:
        try:
            semgrep_findings = await _run_semgrep_on_js(js_contents, log)
            findings.extend(semgrep_findings)
        except Exception as exc:
            await _recon_log(log, "[Recon] semgrep unavailable during analysis — continuing with regex only: {}".format(exc))

    await _recon_log(log, "[Recon] JS analysis complete: {} findings (regex={}, semgrep={})".format(
        len(findings),
        sum(1 for f in findings if f.get("source") == "regex"),
        sum(1 for f in findings if f.get("source") == "semgrep"),
    ))
    return (findings, js_contents) if return_contents else findings


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

    await _recon_log(log, "[Recon] semgrep: {} JS files, {:.1f} MB total".format(
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
                    await _recon_log(log, "[Recon] semgrep: write error {}: {}".format(safe_name, we))

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

            await _recon_log(log, "[Recon] semgrep: {} whole-file chunks (no mid-file splits)".format(
                len(chunks)))

            for chunk_idx, chunk_paths in enumerate(chunks):
                is_large_solo  = len(chunk_paths) == 1 and \
                                  file_sizes.get(chunk_paths[0], 0) >= SEMGREP_LARGE_FILE_MB
                mem_limit      = str(SEMGREP_MAX_MEMORY_MB * 2) if is_large_solo \
                                 else str(SEMGREP_MAX_MEMORY_MB)
                timeout_secs   = SEMGREP_TIMEOUT_SECS * 2 if is_large_solo \
                                 else SEMGREP_TIMEOUT_SECS

                await _recon_log(log, "[Recon] semgrep chunk {}/{}: {} file(s) (mem={}MB, timeout={}s)".format(
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
                        await _recon_log(log, "[Recon] ⚠ PARTIAL_COVERAGE chunk {}: timeout {}s — {} file(s): {}".format(
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
                    await _recon_log(log, "[Recon] semgrep binary gone mid-scan"); break
                except Exception as chunk_err:
                    await _recon_log(log, "[Recon] semgrep chunk {} error: {}".format(chunk_idx+1, chunk_err))
                    continue

    except Exception as outer_err:
        await _recon_log(log, "[Recon] semgrep outer error: {}".format(outer_err))

    await _recon_log(log, "[Recon] semgrep: {} findings | {} chunks | {} coverage gaps".format(
        len(findings), len(chunks) if 'chunks' in dir() else 0, len(coverage_gaps)))
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
    """Run recon with the target itself as the guaranteed starting point."""
    target_url = _target_url(target)
    parsed = urlparse(target_url)
    base_url = "{}://{}".format(parsed.scheme or "http", parsed.netloc)
    hostname = parsed.hostname or parsed.netloc
    ok, reason = scope_policy.validate_target(base_url, action="scan")
    if not ok:
        await _recon_log(log, "[Recon] Blocked by ScopePolicy: {}".format(reason))
        return {
            "domain": hostname,
            "subdomains": [],
            "live_hosts": [],
            "urls": [],
            "js_findings": [],
            "js_contents": {},
            "tech_stack": [],
            "stats": {"subdomains": 0, "live_hosts": 0, "urls_raw": 0,
                      "urls_clustered": 0, "js_findings": 0},
        }

    plan = adaptive_plan or {}
    scan_level = str(plan.get("level", "BALANCED")).upper()
    max_urls = max(50, int(plan.get("max_urls", 200) or 200))
    concurrency = max(1, int(plan.get("concurrency", 4) or 4))
    await _recon_log(
        log,
        "[Recon] ━━━ Phase 1: {} discovery starting on {} ━━━".format(
            scan_level, base_url
        ),
    )

    # Always probe the exact target first. Enumeration is supplemental and can
    # never leave the remaining pipeline without a host.
    live_hosts = []
    initial_body = ""
    transport_url = None
    try:
        allowed, _reason = scope_policy.record_request(base_url, action="scan")
        if not allowed:
            raise PermissionError(_reason)
        response, transport_url, connection_error = (
            await probe_target_connection(base_url)
        )
        if response is None:
            raise RuntimeError(
                connection_error or "All connection attempts failed"
            )
        initial_body = (response.text or "")[:1_500_000]
        tech = []
        server = response.headers.get("server", "")
        powered = response.headers.get("x-powered-by", "")
        if server:
            tech.append(server)
        if powered:
            tech.append(powered)
        body_lower = initial_body[:5000].lower()
        for marker, name in (
            ("react", "React"),
            ("angular", "Angular"),
            ("jquery", "jQuery"),
            ("graphql", "GraphQL"),
            ("wp-content", "WordPress"),
        ):
            if marker in body_lower:
                tech.append(name)
        live_hosts.append({
            "url": base_url,
            "status": response.status_code,
            "tech": list(dict.fromkeys(tech)),
            "title": _extract_title(initial_body),
            "ip": hostname,
        })
        await _recon_log(
            log,
            "[Recon] Direct probe: {} via {} → HTTP {}".format(
                base_url, transport_url, response.status_code
            ),
        )
    except Exception as exc:
        await _recon_log(
            log,
            "[Recon] Direct probe failed: {} — adding as unverified host".format(
                exc
            ),
        )
        live_hosts.append({
            "url": base_url,
            "status": 200,
            "tech": [],
            "title": "Unknown",
            "ip": hostname,
        })

    local_target = _is_local_target(base_url)
    subdomains = [hostname] if hostname else []
    await _recon_log(log, "[Recon] 1a — Subdomain enumeration")
    if local_target:
        await _recon_log(
            log,
            "[Recon] Local target detected — skipping subfinder, using direct probing",
        )
    elif scan_level == "LIGHT":
        await _recon_log(
            log, "[Recon] LIGHT plan: broad subdomain enumeration skipped"
        )
    else:
        try:
            enumerated = await enumerate_subdomains(
                hostname, log, concurrency=concurrency
            )
            subdomains = list(dict.fromkeys(subdomains + list(enumerated or [])))
        except Exception as exc:
            await _recon_log(
                log,
                "[Recon] Subdomain enumeration failed: {} — continuing with target".format(
                    exc
                ),
            )

    # Probe enumerated hosts too, but never replace the direct target.
    additional_subdomains = [
        item for item in subdomains if item and item != hostname
    ]
    if additional_subdomains:
        try:
            extra_hosts = await probe_live_hosts(
                additional_subdomains, log, concurrency=concurrency
            )
            known_urls = {host.get("url") for host in live_hosts}
            live_hosts.extend(
                host for host in extra_hosts
                if host.get("url") and host.get("url") not in known_urls
            )
        except Exception as exc:
            await _recon_log(
                log,
                "[Recon] Supplemental host probing failed: {}".format(exc),
            )

    await _recon_log(log, "[Recon] 1c — URL/endpoint discovery")
    try:
        raw_urls = (
            await discover_local_urls(
                base_url,
                log,
                reachable_url=transport_url,
                max_urls=max_urls,
            )
            if local_target
            else await discover_urls(live_hosts, log, max_urls=max_urls)
        )
    except Exception as exc:
        await _recon_log(
            log,
            "[Recon] External URL discovery failed: {} — using built-in spider".format(
                exc
            ),
        )
        raw_urls = []
    if not local_target and (not tool_available("katana") or not raw_urls):
        raw_urls = list(raw_urls or []) + list(
            await _simple_crawl(base_url, depth=3, max_urls=max_urls)
        )
    for script_src in re.findall(
        r"""(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"'#]+)["']""",
        initial_body,
    ):
        script_url = urljoin(base_url.rstrip("/") + "/", script_src)
        if (
            urlparse(script_url).netloc.lower() == parsed.netloc.lower()
            and scope_policy.validate_target(script_url, action="scan")[0]
        ):
            raw_urls.append(script_url)
    raw_urls = list(dict.fromkeys([base_url] + list(raw_urls or [])))

    # Probe common application and administrative paths for every target.
    _CONTENT_DISCOVERY_STATUS.clear()
    common_probe_paths = (
        FULL_COMMON_PATHS if scan_level == "DEEP" else COMMON_PATHS
    )
    async with httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(3.0),
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (BurpOllama Path Probe)"},
    ) as client:
        common_urls = await _probe_common_paths(
            base_url, client, log, paths=common_probe_paths
        )
    raw_urls.extend(common_urls)

    tech_stack = sorted({
        str(tech)
        for host in live_hosts
        for tech in (host.get("tech") or [])
        if str(tech).strip()
    })
    content_tech_stack = (
        sorted(set(tech_stack + list(TECH_CONTENT_PATHS)))
        if local_target else tech_stack
    )
    try:
        remaining_path_budget = (
            None
            if scan_level == "DEEP"
            else max(0, 50 - len(common_probe_paths))
        )
        content_discovery = await discover_content(
            live_hosts,
            content_tech_stack,
            log,
            concurrency=concurrency,
            max_probes=remaining_path_budget,
            excluded_paths=set(common_probe_paths),
            include_full_paths=scan_level == "DEEP",
        )
    except Exception as exc:
        await _recon_log(
            log, "[Recon] Content discovery failed: {}".format(exc)
        )
        content_discovery = []
    raw_urls.extend(content_discovery)
    raw_urls = scope_policy.filter_urls(
        list(dict.fromkeys(raw_urls))[:max_urls * 4],
        action="scan",
    )
    if not raw_urls:
        raw_urls = [base_url]
    urls = cluster_urls(raw_urls, max_variants=3)
    if base_url not in urls:
        urls.insert(0, base_url)
    urls = list(dict.fromkeys(urls))[:max_urls]
    await _recon_log(
        log,
        "[Recon] URL discovery: {} raw → {} usable URLs".format(
            len(raw_urls), len(urls)
        ),
    )

    # Analyze every discovered script URL. The crawler includes src attributes,
    # including scripts on the initial page.
    await _recon_log(log, "[Recon] 1d — JS file analysis")
    js_findings, js_contents = await analyze_js_files(
        urls[:max_urls], log, return_contents=True
    )
    js_urls = [
        url for url in urls
        if urlparse(url).path.lower().endswith(".js")
        and not urlparse(url).path.lower().endswith(".min.js")
    ]
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
    if base_url not in urls:
        urls.insert(0, base_url)
    urls = list(dict.fromkeys(urls))[:max_urls]
    await _recon_log(
        log,
        "[Recon] JS endpoint extraction found {} additional API endpoints".format(
            len(js_endpoints)
        ),
    )

    websocket_urls = []
    for candidate in raw_urls:
        parsed_candidate = urlparse(candidate)
        if parsed_candidate.scheme in {"ws", "wss"}:
            websocket_urls.append(candidate)
        elif re.search(r"(?i)/(?:ws|websocket|socket\.io)(?:/|$|\?)", parsed_candidate.path):
            websocket_urls.append(candidate.replace("https://", "wss://", 1).replace("http://", "ws://", 1))
    for item in js_findings:
        if item.get("type") != "WebSocket Endpoint":
            continue
        candidate = str(item.get("evidence", "")).strip()
        if not candidate:
            continue
        if candidate.startswith(("ws://", "wss://")):
            websocket_urls.append(candidate)
        else:
            resolved = urljoin(base_url.rstrip("/") + "/", candidate)
            websocket_urls.append(
                resolved.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
            )
    websocket_urls = list(dict.fromkeys(
        url for url in websocket_urls
        if scope_policy.validate_target(url, action="scan")[0]
    ))

    result = {
        "domain":      hostname,
        "subdomains":  subdomains,
        "live_hosts":  live_hosts,
        "tech_stack":  tech_stack,
        "urls":        urls or [base_url],
        "content_discovery": content_discovery,
        "js_endpoints": js_endpoints,
        "js_urls": js_urls,
        "websocket_urls": websocket_urls,
        "js_findings": js_findings,
        "js_contents": js_contents,
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
            "websocket_urls": len(websocket_urls),
            "js_findings":   len(js_findings),
        }
    }

    await _recon_log(
        log,
        "[Recon] ━━━ Phase 1 complete: {} hosts | {} URLs | {} content paths | {} JS findings ━━━".format(
            len(live_hosts), len(result["urls"]), len(content_discovery),
            len(js_findings)
        ),
    )
    return result
