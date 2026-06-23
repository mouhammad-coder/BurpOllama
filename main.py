#!/usr/bin/env python3
"""
BurpOllama v3.1 — Full Automated Pipeline + WAF Fingerprinting + Adaptive Throttle
Gemini-powered: Recon → WAF Check → Hunt → Triage (CoT) → Analysis → Report
+ Burp Suite passive analysis layer
"""

import os
from pathlib import Path
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(env_file)

import asyncio, json, re, sys, time, uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import httpx, uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel

from config_manager import load_project_env, public_settings, save_settings

load_project_env()

from gemini_client import ask_gemini_json, set_api_key
import gemini_client as _gc
from recon_engine  import (
    run_full_recon, run_nuclei_scan,
    COMMON_CONTENT_PATHS, TECH_CONTENT_PATHS, BACKUP_EXTENSIONS,
    probe_target_connection,
)
from recon_intelligence import advanced_recon_intelligence
from program_intelligence import (
    fetch_hackerone_scope,
    lookup_nvd_cve,
    score_program_attractiveness,
)
from fresh_scope_hunter import fresh_scope_hunter
from scope_drift_guard import scope_drift, scope_snapshot
from swarm_blackboard import TriggerPredicate, swarm_blackboard
from hunt_engine   import (
    run_hunt,
    hunt_stored_xss,
    hunt_dom_xss,
    hunt_blind_xss,
    hunt_csrf,
    hunt_path_traversal_lfi,
    hunt_nosql_injection,
    hunt_os_command_injection,
    hunt_host_header_injection,
    hunt_crlf_injection,
    hunt_default_credentials,
    hunt_session_security,
    hunt_clickjacking,
    hunt_browser_storage,
)
from triage_gate   import batch_triage, run_deep_analysis
from reporter      import (
    generate_full_report, generate_submission, generate_executive_report,
    generate_technical_report, generate_json_report, generate_csv_report,
    generate_sarif_report,
)
from waf_engine    import fingerprint_waf, fingerprint_waf_v2, throttle
from utils         import prune_http_for_llm
from proxy_handler import should_queue_for_gemini, pre_filter
from oob_engine    import oob
from schema_parser import ingest_schemas
from dual_session  import auth_matrix
from review_queue  import review_queue
from delta_tracker import delta_tracker
from attack_graph import build_attack_graph
from exploit_chain_engine import build_exploit_chains
from exploit_chain_analyzer import analyze_exploit_chains
from impact_scoring_engine import score_finding as score_impact_finding
from poc_generator import generate_safe_poc
from ato_chain_detector import detect_ato_chains
from ai_provider import ai_router
from coverage_intelligence import compute_coverage, prioritize_urls
from coverage_v2 import compute_coverage_v2
from playbook_engine import build_program_playbook, build_scan_playbook
from distributed_scheduler import scheduler
from observability import metrics
from request_fingerprint import ResponseDeduplicator, fingerprint_http
from storage import event_store
from scope_policy import scope_policy
from ai_privacy import ai_privacy_guard
from finding_model import normalize_finding, normalize_findings
from bounty_mode import build_bounty_mode, build_bounty_report, build_single_bounty_report
from autopilot_state import autopilot_state
from autonomous_planner import WorkingMemory
from auth_coverage_engine import analyze_auth_coverage
from finding_quality import evaluate_findings
from zero_fp_gate import apply_zero_fp_gate
from secret_validator import validate_secret
from business_logic_classifier import classify_business_logic_candidates
from idor_proof_engine import prove_idor
from agent_registry import list_agents
from external_tools import tool_status
from technique_memory import TechniqueMemory
from web3_scanner import audit_solidity_path

STARTUP_TIME = datetime.utcnow().isoformat() + "Z"
_startup_banner_printed = False
from xss_proof_engine import prove_xss
from graphql_auth_tester import test_graphql_auth
from jwt_attack_suite import test_jwt
from oauth_tester import test_oauth_flow
from report_quality_scorer import score_finding
from h1_bugcrowd_reports import (
    generate_bugcrowd_report,
    generate_h1_report,
)
from js_endpoint_extractor import extract_js_endpoints
from behavioral_anomaly_detector import detect_anomalies
from prototype_pollution_tester import test_prototype_pollution
from request_smuggling_detector import detect_smuggling
from api_version_tester import test_api_versions
from websocket_tester import test_websocket_security
from adaptive_scan import (
    AdaptivePlan,
    ResourceController,
    TargetProfile,
    build_adaptive_plan,
    profile_target,
    refine_profile,
)

# ── In-memory state ───────────────────────────────────────────────────────────
scans:          dict[str, dict] = {}
findings_store: list[dict]      = []
ws_clients:     set[WebSocket]  = set()
stats:          dict            = defaultdict(int)
burp_queue:     asyncio.Queue   = asyncio.Queue()
response_deduper = ResponseDeduplicator()
target_profile_cache: dict[str, tuple[float, dict]] = {}


def _remember_hunt_outcomes(raw_findings: list[dict], tech_stack: list[str]) -> None:
    """Persist aggregate detector outcomes without storing response bodies."""
    try:
        memory = TechniqueMemory()
        grouped: dict[str, int] = defaultdict(int)
        for finding in raw_findings:
            grouped[str(finding.get("vuln_type") or "unknown")] += 1
        for vuln_class, count in grouped.items():
            memory.record(
                "hunt-class",
                "findings" if count else "complete",
                vuln_class=vuln_class,
                tech_stack=tech_stack,
                findings_count=count,
            )
    except Exception:
        # Learning persistence must never make a scan fail.
        return

# ── Burp passive patterns ─────────────────────────────────────────────────────
PATTERNS = [
    {"name":"AWS Access Key",       "sev":"CRITICAL","cwe":"CWE-798",
     "re":r"AKIA[0-9A-Z]{16}"},
    {"name":"GitHub Token",         "sev":"CRITICAL","cwe":"CWE-798",
     "re":r"gh[pousr]_[A-Za-z0-9]{36,}"},
    {"name":"Slack Token",          "sev":"CRITICAL","cwe":"CWE-798",
     "re":r"xox[baprs]-[A-Za-z0-9-]{10,}"},
    {"name":"Stripe Key",           "sev":"CRITICAL","cwe":"CWE-798",
     "re":r"sk_(?:live|test)_[A-Za-z0-9]{16,}"},
    {"name":"Generic API Key",      "sev":"CRITICAL","cwe":"CWE-798",
     "re":r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"},
    {"name":"Private Key",          "sev":"CRITICAL","cwe":"CWE-321",
     "re":r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"},
    {"name":"Password in Response", "sev":"HIGH",    "cwe":"CWE-312",
     "re":r"(?i)\"password\"\s*:\s*\"[^\"]{4,}\""},
    {"name":"JWT Token",            "sev":"HIGH",    "cwe":"CWE-522",
     "re":r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"},
    {"name":"JWT alg:none",         "sev":"CRITICAL","cwe":"CWE-327",
     "re":r'"alg"\s*:\s*"none"'},
    {"name":"SQL Error",            "sev":"HIGH",    "cwe":"CWE-89",
     "re":r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|SQLite3::|SQLSTATE|syntax error.*sql)"},
    {"name":"Path Traversal",       "sev":"CRITICAL","cwe":"CWE-22",
     "re":r"(\.\./|%2e%2e%2f|%252e%252e%252f)"},
    {"name":"CORS Wildcard",        "sev":"HIGH",    "cwe":"CWE-942",
     "re":r"(?i)Access-Control-Allow-Origin:\s*\*"},
    {"name":"CORS + Credentials",   "sev":"CRITICAL","cwe":"CWE-942",
     "re":r"(?i)Access-Control-Allow-Credentials:\s*true"},
    {"name":"Debug Endpoint",       "sev":"HIGH",    "cwe":"CWE-215",
     "re":r"(?i)/(debug|test|admin|actuator|metrics|env|console)(\?|/|$)"},
    {"name":"Git Exposure",         "sev":"CRITICAL","cwe":"CWE-538",
     "re":r"(?i)(\.git/HEAD|\.git/config)"},
    {"name":"Env File",             "sev":"CRITICAL","cwe":"CWE-538",
     "re":r"(?i)(\.env|\.env\.local|\.env\.prod)(\?|$)"},
    {"name":"S3 Bucket URL",        "sev":"HIGH",    "cwe":"CWE-284",
     "re":r"(?i)s3\.amazonaws\.com/[a-z0-9\-]+"},
    {"name":"Internal IP",          "sev":"HIGH",    "cwe":"CWE-918",
     "re":r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"},
    {"name":"Stack Trace",          "sev":"MEDIUM",  "cwe":"CWE-209",
     "re":r"(?i)(Traceback \(most recent|NullPointerException|at [A-Za-z]+\.[A-Za-z]+\()"},
    {"name":"SSRF Candidate",       "sev":"HIGH",    "cwe":"CWE-918",
     "re":r"(?i)[?&](url|uri|fetch|load|dest|callback|webhook)=https?://"},
    {"name":"Open Redirect",        "sev":"MEDIUM",  "cwe":"CWE-601",
     "re":r"(?i)[?&](redirect|next|return|goto|target)=https?://"},
    {"name":"Mass Assignment Risk", "sev":"MEDIUM",  "cwe":"CWE-915",
     "re":r'"(isAdmin|is_admin|role|permission|privilege)"\s*:'},
    {"name":"GraphQL Introspection","sev":"MEDIUM",  "cwe":"CWE-200",
     "re":r"(?i)(\"__schema\"|IntrospectionQuery)"},
    {"name":"Source Map",           "sev":"MEDIUM",  "cwe":"CWE-540",
     "re":r"sourceMappingURL=|\.js\.map"},
    {"name":"Firebase URL",         "sev":"HIGH",    "cwe":"CWE-284",
     "re":r"(?i)[a-z0-9\-]+\.firebaseio\.com"},
    {"name":"IDOR Candidate",       "sev":"HIGH",    "cwe":"CWE-639",
     "re":r"(?i)(/api/v?\d*/)(users?|accounts?|orders?)/(\d+|[a-f0-9\-]{36})"},
]

CVSS_MAP  = {"CRITICAL":9.5,"HIGH":7.5,"MEDIUM":5.0,"LOW":2.5,"INFO":0.0}
REMED_MAP = {
    "AWS Access Key":       "Rotate immediately. Use IAM roles, never long-term keys.",
    "GitHub Token":         "Revoke at github.com/settings/tokens. Enable secret scanning.",
    "Slack Token":          "Revoke the Slack token and rotate the associated app credential.",
    "Stripe Key":           "Roll the Stripe key immediately and review read-only access logs.",
    "Generic API Key":      "Move to environment variables / secret vault.",
    "Private Key":          "Revoke certificate immediately. Never transmit private keys.",
    "Password in Response": "Never return passwords in responses. Hash server-side.",
    "JWT Token":            "Use short expiry + refresh tokens. Validate algorithm server-side.",
    "JWT alg:none":         "CRITICAL: Reject alg:none. Hardcode expected algorithm.",
    "SQL Error":            "Use parameterized queries. Suppress DB errors in production.",
    "Path Traversal":       "Canonicalize paths. Reject traversal sequences.",
    "CORS Wildcard":        "Restrict to explicit trusted origins.",
    "CORS + Credentials":   "Validate Origin against strict server-side whitelist.",
    "Debug Endpoint":       "Remove or auth-protect all debug endpoints.",
    "Git Exposure":         "Block /.git/ in web server config. Rotate exposed credentials.",
    "Env File":             "Block .env files. Audit what was exposed.",
    "S3 Bucket URL":        "Verify no public ListBucket/GetObject. Apply bucket policies.",
    "Internal IP":          "Never return internal IPs in API responses.",
    "Stack Trace":          "Disable verbose errors in production.",
    "SSRF Candidate":       "Validate URLs. Block internal IP ranges.",
    "Open Redirect":        "Whitelist allowed redirect destinations.",
    "Mass Assignment Risk": "Whitelist allowed fields in request binding.",
    "GraphQL Introspection":"Disable introspection in production.",
    "Source Map":           "Block *.map files in production.",
    "Firebase URL":         "Verify Firebase rules deny unauthenticated access.",
    "IDOR Candidate":       "Implement server-side authorization on every object access.",
}

# ── Pydantic models ───────────────────────────────────────────────────────────
class BurpTraffic(BaseModel):
    request_method:   str
    request_url:      str
    request_headers:  str
    request_body:     Optional[str] = ""
    response_status:  Optional[int] = 200
    response_headers: Optional[str] = ""
    response_body:    Optional[str] = ""
    source:           Optional[str] = "burp"

class ScanRequest(BaseModel):
    target:  str
    api_key: Optional[str] = ""
    scan_mode: Optional[str] = None
    authorization_confirmed: bool = False

class SessionConfig(BaseModel):
    session_a_cookie: Optional[str] = ""
    session_a_token:  Optional[str] = ""
    session_b_cookie: Optional[str] = ""
    session_b_token:  Optional[str] = ""
    session_a_role: Optional[str] = "Attacker / lower privilege"
    session_b_role: Optional[str] = "Victim / higher privilege"
    session_a_headers: Optional[dict[str, str]] = None
    session_b_headers: Optional[dict[str, str]] = None
    session_a_expires_at: Optional[int] = None
    session_b_expires_at: Optional[int] = None
    health_check_endpoint: Optional[str] = ""
    allow_mutations: bool = False

class TargetValidationRequest(BaseModel):
    target: str
    action: Optional[str] = "scan"

class AutopilotResumeRequest(BaseModel):
    scan_id: str
    resume_token: Optional[str] = ""

class FreshScopeAuthorizationRequest(BaseModel):
    platform: str
    program_id: str
    asset_patterns: list[str]
    authorization_confirmed: bool = False

class ReviewNoteRequest(BaseModel):
    note: str

class ScanStopped(Exception):
    pass

# ── Broadcast helpers ─────────────────────────────────────────────────────────
async def broadcast(data: dict):
    metrics.inc("websocket.broadcast")
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)

async def log_broadcast(scan_id: str, msg: str, level: str = "info"):
    ts    = datetime.utcnow().strftime("%H:%M:%S")
    entry = {"ts": ts, "msg": msg, "level": level}
    if scan_id in scans:
        scans[scan_id].setdefault("logs", []).append(entry)
    await broadcast({"type": "log", "scan_id": scan_id, "entry": entry})
    print("[{}] {}".format(scan_id[:8], msg))
    event_store.append(scan_id, "log.{}".format(level), {"message": msg})
    autopilot_state.event(scan_id, "log.{}".format(level), entry)

async def enforce_scan_control(scan_id: str):
    if scope_policy.config.emergency_stop:
        raise ScanStopped("Emergency stop is enabled.")
    scan = scans.get(scan_id, {})
    if scan.get("control") == "stop" or scan.get("status") == "stopped":
        raise ScanStopped("Scan stopped by user.")
    while scan.get("control") == "pause" or scan.get("status") == "paused":
        scan["status"] = "paused"
        await broadcast({"type": "scan_paused", "scan_id": scan_id})
        await asyncio.sleep(1)
        if scope_policy.config.emergency_stop:
            raise ScanStopped("Emergency stop is enabled.")
        scan = scans.get(scan_id, {})
        if scan.get("control") == "stop":
            raise ScanStopped("Scan stopped by user.")
    if scan.get("status") == "paused":
        scan["status"] = "running"
        await broadcast({"type": "scan_resumed", "scan_id": scan_id})

# ── Burp pattern scanner ──────────────────────────────────────────────────────
async def pattern_scan_traffic(payload: BurpTraffic) -> list[dict]:
    text  = "\n".join([
        payload.request_url,
        payload.request_headers,
        payload.request_body or "",
        payload.response_headers or "",
        payload.response_body or "",
    ])
    # Prune before pattern scanning
    pruned_text = text
    results, seen = [], set()
    for p in PATTERNS:
        allowed_class, _ = scope_policy.vulnerability_allowed(p["name"])
        if not allowed_class:
            continue
        if p["name"] in seen:
            continue
        m = re.search(p["re"], pruned_text)
        if m:
            seen.add(p["name"])
            secret_value = m.group(2) if p["name"] == "Generic API Key" and m.lastindex and m.lastindex >= 2 else m.group(0)
            is_secret = p["name"] in {
                "AWS Access Key", "GitHub Token", "Slack Token",
                "Stripe Key", "Generic API Key", "JWT Token",
            }
            validation = None
            if p["sev"] == "CRITICAL" and is_secret:
                validation = await validate_secret(
                    p["name"],
                    secret_value,
                    payload.request_url,
                )
            def redact_secret_text(value: str) -> str:
                redacted = ai_privacy_guard.redact(value)
                if secret_value:
                    redacted = redacted.replace(secret_value, "[REDACTED_SECRET]")
                return redacted
            finding_data = {
                "id":          "P-{}-{}".format(int(time.time()*1000), len(findings_store)),
                "timestamp":   datetime.utcnow().isoformat(),
                "source":      "burp-pattern",
                "vuln_type":   p["name"],
                "severity":    p["sev"],
                "confidence":  92,
                "url":         payload.request_url,
                "method":      payload.request_method,
                "description": "Pattern match: {} in intercepted traffic.".format(p["name"]),
                "evidence":    (
                    "{} detected: {}".format(
                        p["name"],
                        validation.get("redacted_value", "[REDACTED]") if validation else "[REDACTED]",
                    )
                    if is_secret else m.group(0)[:200]
                ),
                "remediation": REMED_MAP.get(p["name"], "Review manually."),
                "cwe":         p.get("cwe",""),
                "cvss":        CVSS_MAP.get(p["sev"], 0.0),
                "verdict":     "PASS",
                "triaged":     False,
                # Store raw HTTP for triage pruning
                "raw_request_headers":  redact_secret_text(payload.request_headers) if is_secret else payload.request_headers,
                "raw_request_body":     redact_secret_text(payload.request_body or "") if is_secret else payload.request_body or "",
                "raw_response_headers": redact_secret_text(payload.response_headers or "") if is_secret else payload.response_headers or "",
                "raw_response_body":    redact_secret_text(payload.response_body or "") if is_secret else payload.response_body or "",
                "redaction_status": "redacted" if is_secret else "not_required",
            }
            if validation is not None:
                finding_data["secret_validation"] = validation
                finding_data["secret_validation_status"] = validation.get("valid")
                finding_data["business_impact"] = validation.get("bounty_note", "")
                if validation.get("severity_upgrade"):
                    finding_data["severity"] = "CRITICAL"
                    finding_data["confidence"] = 99
                    finding_data["exploitability_status"] = "confirmed"
                    finding_data["evidence_strength"] = "strong"
                    finding_data["false_positive_risk"] = "low"
            results.append(normalize_finding(finding_data))
    return results

# ── Gemini deep Burp traffic analysis ────────────────────────────────────────
BURP_SYSTEM = """You are an elite bug bounty hunter analyzing live HTTP traffic.
Find REAL exploitable vulnerabilities with concrete evidence.
Respond ONLY with a valid JSON array."""

async def gemini_analyze_traffic(payload: BurpTraffic, api_key: str) -> list[dict]:
    # Prune before sending to LLM
    pruned = prune_http_for_llm(
        request_headers  = payload.request_headers,
        request_body     = payload.request_body or "",
        response_headers = payload.response_headers or "",
        response_body    = payload.response_body or "",
        finding_type     = "generic",
    )
    prompt = """Analyze this intercepted HTTP exchange for vulnerabilities.

=== REQUEST ===
{method} {url}
{req_h}
{req_b}

=== RESPONSE (HTTP {status}) ===
{resp_h}
{resp_b}

Hunt for: auth flaws, IDOR, JWT weaknesses, business logic, secrets, injection,
SSRF, XSS, CSRF, CORS, rate-limit bypass, hidden endpoints, mass assignment, OAuth/SAML.

Return JSON array only ([] if nothing found):
[{{
  "vuln_type":"name","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence":85,"description":"what and why exploitable",
  "evidence":"exact snippet","remediation":"fix","cwe":"CWE-XXX","cvss":7.5
}}]""".format(
        method = payload.request_method,
        url    = payload.request_url,
        req_h  = pruned["pruned_request_headers"][:1000],
        req_b  = pruned["pruned_request_body"][:1000],
        status = payload.response_status,
        resp_h = pruned["pruned_response_headers"][:600],
        resp_b = pruned["pruned_response_body"][:4000],
    )
    metrics.inc("ai.burp_analysis.queued")
    results = await ask_gemini_json(prompt, system=BURP_SYSTEM, api_key=api_key)
    return results if isinstance(results, list) else []

# ── Burp queue worker ─────────────────────────────────────────────────────────
async def burp_worker():
    while True:
        payload, api_key = await burp_queue.get()
        try:
            llm_hits = await gemini_analyze_traffic(payload, api_key)
            metrics.inc("burp_worker.llm_batches")
            for r in llm_hits:
                allowed_class, _ = scope_policy.vulnerability_allowed(r.get("vuln_type", "Unknown"))
                if not allowed_class:
                    continue
                f = normalize_finding({
                    "id":          "G-{}-{}".format(int(time.time()*1000), len(findings_store)),
                    "timestamp":   datetime.utcnow().isoformat(),
                    "source":      "burp-gemini",
                    "vuln_type":   r.get("vuln_type","Unknown"),
                    "severity":    r.get("severity","INFO").upper(),
                    "confidence":  max(0, min(100, int(r.get("confidence",70)))),
                    "url":         payload.request_url,
                    "method":      payload.request_method,
                    "description": r.get("description",""),
                    "evidence":    str(r.get("evidence",""))[:400],
                    "remediation": r.get("remediation",""),
                    "cwe":         r.get("cwe",""),
                    "cvss":        float(r.get("cvss",0.0)),
                    "verdict":     "PASS",
                    "triaged":     False,
                })
                findings_store.append(f)
                stats[f["severity"]] += 1
                stats["total"]        += 1
                await broadcast({"type":"finding","data":f})
                await broadcast({"type":"stats","data":dict(stats)})
        except Exception as e:
            print("[BurpWorker] {}".format(e))
        finally:
            burp_queue.task_done()

# ── Full automated pipeline ───────────────────────────────────────────────────
CHECKPOINT_PHASES = ("recon", "hunt", "triage", "analysis", "report", "intelligence")


def _checkpoint_json(value):
    """Return a JSON-safe copy suitable for durable event payloads."""
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return {}


def _minimal_recon_summary(scan: dict) -> dict:
    recon = scan.get("recon") or {}
    stats_data = recon.get("stats") or {}
    return {
        "subdomains": int(stats_data.get("subdomains", 0) or 0),
        "live_hosts": int(stats_data.get("live_hosts", 0) or 0),
        "urls_raw": int(stats_data.get("urls_raw", 0) or 0),
        "urls_clustered": int(stats_data.get("urls_clustered", 0) or 0),
        "content_discovery": int(stats_data.get("content_discovery", 0) or 0),
        "js_endpoints": int(stats_data.get("js_endpoints", 0) or 0),
        "js_findings": int(stats_data.get("js_findings", 0) or 0),
    }


def _checkpoint_findings_count(scan: dict) -> int:
    return len(
        scan.get("triaged_findings")
        or scan.get("raw_findings")
        or []
    )


def _fallback_scan_intelligence(
    findings: list[dict],
    recon_data: dict,
    attack_graph_data: dict,
    coverage_data: dict,
) -> dict:
    severity_counts = defaultdict(int)
    manual_candidates = []
    seen_urls = set()
    for finding in findings or []:
        severity_counts[str(finding.get("severity", "INFO")).upper()] += 1
        status = str(finding.get("exploitability_status", "")).lower()
        verdict = str(finding.get("verdict", "")).upper()
        if status not in {"needs_manual_validation", "candidate", "probable"} and verdict != "DOWNGRADE":
            continue
        url = str(finding.get("affected_url") or finding.get("url") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        severity = str(finding.get("severity", "MEDIUM")).upper()
        manual_candidates.append({
            "url": url,
            "reason": "{} requires manual validation before submission.".format(
                finding.get("vuln_type") or finding.get("title") or "Candidate finding"
            ),
            "what_to_test": str(
                finding.get("manual_test_description")
                or finding.get("safe_reproduction_steps")
                or finding.get("reproduction_steps")
                or "Reproduce with an authorized test account and compare the baseline response."
            )[:600],
            "estimated_bounty_value": (
                "High" if severity in {"CRITICAL", "HIGH"}
                else "Medium" if severity == "MEDIUM"
                else "Low"
            ),
        })

    coverage_targets = (
        coverage_data.get("high_risk_untested_urls")
        or coverage_data.get("top_untested")
        or []
    )
    for target in coverage_targets:
        if len(manual_candidates) >= 8:
            break
        url = str(target.get("url") if isinstance(target, dict) else target).strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        reasons = target.get("reasons", []) if isinstance(target, dict) else []
        manual_candidates.append({
            "url": url,
            "reason": "High-value coverage gap{}".format(
                ": {}".format(", ".join(map(str, reasons[:3]))) if reasons else ""
            ),
            "what_to_test": "Review authentication, authorization, input handling, and business-logic boundaries manually.",
            "estimated_bounty_value": "Medium",
        })

    technologies = recon_data.get("tech_stack") or recon_data.get("technologies") or []
    if isinstance(technologies, dict):
        technologies = list(technologies.keys())
    technologies = [str(item) for item in technologies if item][:8]
    reportable = sum(
        1 for finding in findings or []
        if finding.get("verdict") in ("PASS", "DOWNGRADE")
    )
    gaps = int(
        coverage_data.get("untested_endpoints")
        or coverage_data.get("untested_templates")
        or 0
    )
    attack_paths = attack_graph_data.get("attack_paths") or []
    candidate_count = len(manual_candidates)
    estimated_hours = max(1, min(24, candidate_count * 1.25 + gaps * 0.15))
    low_hours = max(1, round(estimated_hours * 0.75))
    high_hours = max(low_hours + 1, round(estimated_hours * 1.35))

    return {
        "executive_summary": (
            "The scan identified {} reportable finding(s), including {} critical and {} high-severity item(s). "
            "{} endpoint(s) remain untested or need deeper manual validation."
        ).format(
            reportable,
            severity_counts["CRITICAL"],
            severity_counts["HIGH"],
            gaps,
        ),
        "top_manual_targets": manual_candidates[:8],
        "technology_specific_advice": (
            "Prioritize authorization, configuration exposure, and framework-specific debug surfaces for {}."
            .format(", ".join(technologies))
            if technologies
            else "The technology stack was not conclusive; prioritize authorization, business logic, API versioning, and exposed debug surfaces."
        ),
        "coverage_gap_advice": (
            "Manually review the {} untested endpoint(s), beginning with authenticated, administrative, and state-changing routes."
        ).format(gaps),
        "chain_opportunities": (
            "Review {} attack-graph path(s) for combinations that turn individual findings into account takeover or broader data access."
        ).format(len(attack_paths)),
        "time_estimate": "{}-{} hours of focused manual validation.".format(low_hours, high_hours),
    }


def _normalize_scan_intelligence(value: dict, fallback: dict) -> dict:
    source = value if isinstance(value, dict) else {}
    normalized = {}
    text_fields = (
        "executive_summary",
        "technology_specific_advice",
        "coverage_gap_advice",
        "chain_opportunities",
        "time_estimate",
    )
    for field in text_fields:
        candidate = source.get(field)
        normalized[field] = (
            str(candidate).strip()
            if isinstance(candidate, (str, int, float)) and str(candidate).strip()
            else fallback[field]
        )

    targets = []
    for item in source.get("top_manual_targets", []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        reason = str(item.get("reason", "")).strip()
        what_to_test = str(item.get("what_to_test", "")).strip()
        value_label = str(item.get("estimated_bounty_value", "Medium")).title()
        if not url or not reason or not what_to_test:
            continue
        if value_label not in {"High", "Medium", "Low"}:
            value_label = "Medium"
        targets.append({
            "url": url,
            "reason": reason,
            "what_to_test": what_to_test,
            "estimated_bounty_value": value_label,
        })
        if len(targets) >= 8:
            break
    normalized["top_manual_targets"] = targets or fallback["top_manual_targets"]
    return normalized


async def generate_scan_intelligence(
    scan_id: str,
    findings: list[dict],
    recon_data: dict,
    attack_graph_data: dict,
    coverage_data: dict,
    api_key: str,
) -> dict:
    """Generate a compact analyst briefing without exposing raw evidence to AI."""
    fallback = _fallback_scan_intelligence(
        findings,
        recon_data,
        attack_graph_data,
        coverage_data,
    )
    finding_summary = []
    for finding in (findings or [])[:100]:
        finding_summary.append({
            "id": finding.get("id", ""),
            "vuln_type": finding.get("vuln_type") or finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "url": finding.get("affected_url") or finding.get("url", ""),
            "method": finding.get("method", ""),
            "parameter": finding.get("parameter", ""),
            "exploitability_status": finding.get("exploitability_status", ""),
            "verdict": finding.get("verdict", ""),
            "manual_test_description": finding.get("manual_test_description", ""),
        })
    path_summary = []
    for path in (attack_graph_data.get("attack_paths") or [])[:10]:
        if not isinstance(path, dict):
            continue
        path_summary.append({
            "summary": path.get("summary", ""),
            "chain_label": path.get("chain_label", ""),
            "impact": path.get("impact", ""),
            "score": path.get("score", 0),
            "steps": path.get("steps", 0),
        })
    intelligence_input = {
        "scan_id": scan_id,
        "findings": finding_summary,
        "recon": {
            "stats": recon_data.get("stats", {}),
            "tech_stack": recon_data.get("tech_stack") or recon_data.get("technologies") or [],
            "live_hosts": recon_data.get("live_hosts", [])[:50],
        },
        "attack_graph": {
            "path_count": attack_graph_data.get("path_count", 0),
            "attack_paths": path_summary,
        },
        "coverage": {
            "coverage_percent": coverage_data.get("coverage_percent", 0),
            "untested_endpoints": coverage_data.get(
                "untested_endpoints",
                coverage_data.get("untested_templates", 0),
            ),
            "high_risk_untested_urls": (
                coverage_data.get("high_risk_untested_urls")
                or coverage_data.get("top_untested")
                or []
            )[:20],
        },
    }
    prompt = """Create an analyst intelligence briefing for an authorized security scan.
Return one JSON object with exactly these keys:
executive_summary, top_manual_targets, technology_specific_advice,
coverage_gap_advice, chain_opportunities, time_estimate.

executive_summary must be 2-3 plain-English sentences.
top_manual_targets must contain at most 8 objects with url, reason,
what_to_test, and estimated_bounty_value (High, Medium, or Low).
Give concrete, safe manual validation advice. Do not invent confirmed
vulnerabilities or URLs. Treat candidate findings as unconfirmed.

SCAN DATA:
{}""".format(json.dumps(intelligence_input, default=str))
    try:
        result = await ai_router.complete_json(
            prompt,
            system=(
                "You are a senior application-security analyst. Produce concise, "
                "evidence-grounded JSON only and never claim exploitation without proof."
            ),
            temperature=0.1,
            max_tokens=1800,
            api_key=api_key or "",
        )
    except Exception:
        result = {}
    return _normalize_scan_intelligence(result, fallback)


async def _save_scan_transition(scan_id: str, phase_name: str):
    scan = scans[scan_id]
    scan["phase"] = phase_name
    event_store.append(
        stream_id=scan_id,
        event_type="scan.state",
        payload={
            "phase": phase_name,
            "status": scan.get("status", "running"),
            "scan": _checkpoint_json(scan),
        },
    )
    await broadcast({
        "type": "phase_change",
        "scan_id": scan_id,
        "phase": phase_name,
    })


def _save_phase_checkpoint(scan_id: str, phase_name: str):
    scan = scans[scan_id]
    event_store.append(
        stream_id=scan_id,
        event_type="phase_complete",
        payload={
            "phase": phase_name,
            "findings_count": _checkpoint_findings_count(scan),
            "recon_summary": _minimal_recon_summary(scan),
            "scan": _checkpoint_json(scan),
        },
    )


def _decode_event_payload(event: dict) -> dict:
    payload = event.get("payload")
    if isinstance(payload, dict):
        return payload
    raw = event.get("payload_json", "")
    try:
        parsed = json.loads(raw or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def _checkpoint_state(scan_id: str) -> tuple[set[str], dict]:
    completed: set[str] = set()
    latest_scan: dict = {}
    events = event_store.stream(scan_id, limit=1000)
    # stream() returns newest first. First snapshot encountered is the latest.
    for event in events:
        payload = _decode_event_payload(event)
        if not latest_scan and isinstance(payload.get("scan"), dict):
            latest_scan = payload["scan"]
        if event.get("event_type") == "phase_complete":
            phase = str(payload.get("phase", ""))
            if phase in CHECKPOINT_PHASES:
                completed.add(phase)
    return completed, latest_scan


def _restore_checkpoint_findings(scan_id: str, scan: dict):
    restored = normalize_findings(
        scan.get("triaged_findings")
        or scan.get("raw_findings")
        or [],
        scan_id=scan_id,
    )
    existing_ids = {
        finding.get("id")
        for finding in findings_store
        if finding.get("scan_id") == scan_id
    }
    for finding in restored:
        if finding.get("id") in existing_ids:
            continue
        findings_store.append(finding)
        existing_ids.add(finding.get("id"))
        stats[finding.get("severity", "INFO")] += 1
        stats["total"] += 1


async def run_pipeline(scan_id: str, target: str, api_key: str):
    recon_data = {}
    raw_findings = []
    triaged_findings = []
    scan_logs = []
    coverage_data = {}
    attack_graph_data = {}
    intel_data = {}
    scan = scans[scan_id]
    stored_run = autopilot_state.get_run(scan_id) or {}
    stored_planner = (
        scan.get("planner")
        or stored_run.get("checkpoint", {}).get("planner")
        or {}
    )
    planner = (
        WorkingMemory.from_dict(stored_planner)
        if stored_planner
        else WorkingMemory(
            step_budget=int(os.getenv("BURPOLLAMA_PLANNER_STEP_BUDGET", "100")),
            time_budget=int(os.getenv("BURPOLLAMA_PLANNER_TIME_BUDGET", "1800")),
        )
    )
    scan_logs = scan.setdefault("logs", scan_logs)
    scan["status"] = "running"
    scan["scope_snapshot"] = scope_snapshot(scope_policy.to_dict())
    task_id = scan.get("scheduler_task_id", "")
    autopilot_state.update_run(scan_id, status="running", phase=scan.get("phase", "queued"))
    autopilot_state.upsert_task(scan_id, "full_pipeline", "running", {"target": target})

    async def log(msg, level="info"):
        await log_broadcast(scan_id, msg, level)

    def swarm_write(
        agent_name: str,
        finding_type: str,
        item_target: str,
        data: dict,
        pheromone: float,
    ):
        try:
            return swarm_blackboard.write(
                scan_id,
                agent_name,
                finding_type,
                item_target,
                data,
                pheromone_base=pheromone,
            )
        except Exception as exc:
            event_store.append(
                scan_id,
                "swarm.write_error",
                {"agent": agent_name, "type": finding_type, "error": str(exc)},
            )
            return ""

    async def planner_checkpoint(phase_name: str):
        drift = scope_drift(scan.get("scope_snapshot"), scope_policy.to_dict())
        if drift["changed"]:
            scan["scope_drift"] = drift
            allowed, reason = scope_policy.validate_target(target, action="scan")
            await log(
                "Scope policy changed during scan before {}: {}".format(
                    phase_name,
                    ", ".join(sorted(drift["changes"])),
                ),
                "warning",
            )
            if not allowed:
                swarm_write(
                    "scope-guard",
                    "AGENT_ERROR",
                    target,
                    {"reason": reason, "changes": drift["changes"]},
                    1.0,
                )
                raise ScanStopped("Scope drift blocked target: {}".format(reason))
            scan["scope_snapshot"] = drift["snapshot"]
        scan["planner"] = planner.to_dict()
        autopilot_state.update_run(
            scan_id,
            checkpoint={
                "planner": scan["planner"],
                "planner_phase": phase_name,
            },
        )
        if planner.should_continue():
            return
        scan["planner_summary"] = planner.summarize_progress()
        await log(
            "Planner budget reached before {}. Remaining work stopped safely.".format(
                phase_name
            ),
            "warning",
        )
        raise ScanStopped("Planner budget exceeded")

    async def progress(phase, current, total, label=""):
        scan["phase"]    = phase
        scan["progress"] = {"current": current, "total": total, "label": label}
        autopilot_state.update_run(scan_id, status=scan.get("status", "running"), phase=phase,
                                   checkpoint={"progress": scan["progress"]})
        autopilot_state.upsert_task(scan_id, phase, "running", scan["progress"])
        await broadcast({"type": "progress", "scan_id": scan_id,
                         "phase": phase, "current": current,
                         "total": total, "label": label})

    async def throttle_broadcast(data):
        data["scan_id"] = scan_id
        scan["throttle"] = data.get("status_snapshot") or throttle.status()
        if data.get("type") == "throttle_warning":
            await log_broadcast(scan_id, "{}: {}. {}".format(
                data.get("message", "Target is blocking requests"),
                data.get("reason", "requests are being slowed"),
                data.get("recommendation", "")
            ), "warning")
        await broadcast(data)
    throttle.set_broadcast(throttle_broadcast)
    delta_tracker.set_broadcast(broadcast)
    auth_matrix.set_broadcast(broadcast)

    try:
        event_store.append(scan_id, "scan.started", {"target": target})
        swarm_write(
            "autopilot",
            "TARGET_REGISTERED",
            target,
            {"scan_mode": scope_policy.config.scan_mode},
            1.0,
        )
        if scan.get("authorization_warning"):
            await log(scan["authorization_warning"], "warning")
        await enforce_scan_control(scan_id)
        await progress("profiling", 1, 1, "Analyzing target behavior")
        cached_profile = target_profile_cache.get(target)
        if cached_profile and time.time() - cached_profile[0] <= 300:
            target_profile = TargetProfile(**cached_profile[1])
            await log("Using recent authorized target profile.", "adaptive")
        else:
            try:
                target_profile = await profile_target(target, scope_policy, log)
            except Exception as e:
                await log("Profiling error: {}".format(e), "error")
                target_profile = TargetProfile(
                    target=target,
                    reasons=["Profiling failed; using safe default scan plan."],
                )
        adaptive_plan = build_adaptive_plan(
            target_profile,
            scan.get("requested_scan_mode", ""),
        )
        if recon_data.get("websocket_urls"):
            adaptive_plan.enabled_modules = sorted(set(
                adaptive_plan.enabled_modules + ["WebSocket Active Security"]
            ))
        if recon_data.get("js_urls"):
            adaptive_plan.enabled_modules = sorted(set(
                adaptive_plan.enabled_modules + ["Browser Storage Security"]
            ))
        resources = ResourceController(
            cpu_limit_percent=adaptive_plan.cpu_limit_percent
        )
        scan["target_profile"] = target_profile.to_dict()
        scan["adaptive_plan"] = adaptive_plan.to_dict()
        scan["resource_control"] = resources.status()
        await broadcast({
            "type": "target_profile",
            "scan_id": scan_id,
            "data": scan["target_profile"],
        })
        await broadcast({
            "type": "adaptive_plan",
            "scan_id": scan_id,
            "data": scan["adaptive_plan"],
        })
        await log(
            "Target Profile: {} | Recommended Scan: {} SCAN".format(
                target_profile.profile_type,
                adaptive_plan.level,
            ),
            "success",
        )
        for message in adaptive_plan.progress_messages:
            await log(message, "adaptive")
        await resources.gate()
        # PHASE 1: RECON
        await planner_checkpoint("recon")
        await _save_scan_transition(scan_id, "recon")
        await log("P1: RECON", "phase")
        def recon_log(msg, level="info"):
            asyncio.create_task(log(msg, level))
        try:
            with metrics.span("phase.recon", scan_id=scan_id):
                recon_data = await run_full_recon(
                    target,
                    recon_log,
                    adaptive_plan=adaptive_plan.to_dict(),
                )
        except Exception as e:
            await log("Recon phase error: {}".format(str(e)), "error")
            recon_data = {
                "urls": [],
                "live_hosts": [{"url": target, "tech": [], "status": 200}],
                "js_findings": [],
                "js_contents": {},
                "subdomains": [],
            }
        previous_level = adaptive_plan.level
        target_profile = refine_profile(target_profile, recon_data)
        adaptive_plan = build_adaptive_plan(
            target_profile,
            scan.get("requested_scan_mode", ""),
        )
        resources.cpu_limit_percent = adaptive_plan.cpu_limit_percent
        scan["target_profile"] = target_profile.to_dict()
        scan["adaptive_plan"] = adaptive_plan.to_dict()
        if adaptive_plan.level != previous_level:
            await log(
                "Adaptive scan level changed: {} -> {} ({})".format(
                    previous_level,
                    adaptive_plan.level,
                    adaptive_plan.reason,
                ),
                "adaptive",
            )
        await broadcast({
            "type": "adaptive_plan",
            "scan_id": scan_id,
            "data": scan["adaptive_plan"],
        })
        try:
            recon_data["intelligence"] = await advanced_recon_intelligence(
                target,
                recon_data.get("urls", []),
                recon_data.get("js_contents", {}),
                [
                    host.get("url", "")
                    for host in recon_data.get("live_hosts", [])
                    if isinstance(host, dict) and host.get("url")
                ],
                recon_data.get("tech_stack")
                or recon_data.get("technologies")
                or [],
            )
            await log(
                "Recon intelligence: {} hidden endpoints | {} high-value targets".format(
                    len(recon_data["intelligence"].get("hidden_endpoints", [])),
                    len(recon_data["intelligence"].get("high_value_targets", [])),
                ),
                "success",
            )
        except Exception as e:
            await log("Recon intelligence error: {}".format(e), "error")
            recon_data["intelligence"] = {}
        scan["recon"] = recon_data
        autopilot_state.output(scan_id, "recon", "recon_data", {
            "stats": recon_data.get("stats", {}),
            "content_discovery_count": len(recon_data.get("content_discovery", [])),
        })
        for host in recon_data.get("live_hosts", [])[:100]:
            if not isinstance(host, dict):
                continue
            swarm_write(
                "recon-agent",
                "HTTP_ENDPOINT",
                host.get("url", target),
                {
                    "status": host.get("status"),
                    "title": host.get("title", ""),
                    "tech": host.get("tech", []),
                },
                0.65,
            )
        for technology in (
            recon_data.get("tech_stack")
            or recon_data.get("technologies")
            or []
        )[:100]:
            swarm_write(
                "recon-agent",
                "TECHNOLOGY",
                target,
                {"technology": technology},
                0.5,
            )
        await enforce_scan_control(scan_id)
        await broadcast({"type": "recon_complete", "scan_id": scan_id,
                         "data": {"stats": recon_data.get("stats", {}),
                                  "live_hosts": recon_data.get("live_hosts", [])[:20]}})
        for jf in recon_data.get("js_findings", []):
            sev = jf.get("severity", "HIGH" if any(
                k in jf.get("type","") for k in ["Key","Secret","JWT","Token","AWS","Firebase"]
            ) else "MEDIUM")
            f = normalize_finding({
                "id":          "JS-{}-{}".format(int(time.time()*1000), len(findings_store)),
                "timestamp":   datetime.utcnow().isoformat(),
                "source":      "js-{}".format(jf.get("source","analysis")),
                "vuln_type":   jf.get("type","JS Finding"),
                "severity":    sev,
                "confidence":  90 if jf.get("source")=="semgrep" else 85,
                "url":         jf.get("file", target),
                "method":      "GET",
                "description": "{} — {}".format(jf.get("type",""),
                    jf.get("message","Found in JavaScript file.")[:200]),
                "evidence":    jf.get("evidence","")[:300],
                "remediation": "Remove secrets from client-side code.",
                "cwe": "CWE-798", "cvss": 7.5, "verdict": "PASS", "triaged": False,
            }, scan_id=scan_id)
            findings_store.append(f)
            stats[f["severity"]] += 1; stats["total"] += 1
            await broadcast({"type": "finding", "data": f})
        delta_tracker.register_mode1_surface(recon_data.get("urls", []))
        recon_stats = recon_data.get("stats", {})
        await log("Recon: {} hosts | {} URLs | {} JS findings".format(
            recon_stats.get("live_hosts", 0),
            recon_stats.get("urls_clustered", recon_stats.get("urls", 0)),
            recon_stats.get("js_findings", 0)), "success")
        planner.record_step(
            "Recon",
            "completed",
            len(recon_data.get("js_findings", [])),
        )
        scan["planner"] = planner.to_dict()

        # PHASE 1.5a: OOB REGISTRATION
        await planner_checkpoint("OOB registration")
        await enforce_scan_control(scan_id)
        await log("P1.5a: OOB ENGINE", "phase")
        oob_started = False
        oob_relevant = any(name in adaptive_plan.enabled_modules for name in (
            "SSRF", "SQL Injection", "OS Command Injection", "Blind XSS"
        ))
        if (
            oob_relevant
            and scope_policy.config.oob_testing_enabled
            and not scope_policy.config.passive_only_mode
        ):
            try:
                oob_started = await oob.start(log)
            except Exception as e:
                await log("OOB startup error: {}".format(e), "error")
                oob_started = False
        else:
            await log("OOB disabled by ScopePolicy", "warning")
        if oob_started:
            scan["oob_domain"] = oob.domain
            await broadcast({"type": "oob_ready", "scan_id": scan_id, "domain": oob.domain})

        # PHASE 1.5b: WAF FINGERPRINTING
        await planner_checkpoint("WAF fingerprinting")
        waf_info = {}
        allowed_live_hosts = [
            h for h in recon_data.get("live_hosts", [])
            if scope_policy.validate_target(h.get("url", ""), action="scan")[0]
        ]
        if allowed_live_hosts:
            await enforce_scan_control(scan_id)
            scan["phase"] = "waf_check"
            await broadcast({"type": "phase_change", "scan_id": scan_id, "phase": "waf_check"})
            await log("P1.5b: WAF FINGERPRINTING", "phase")
            try:
                waf_info = await fingerprint_waf_v2(allowed_live_hosts[0]["url"], log)
            except Exception as e:
                await log("WAF fingerprint error: {}".format(e), "error")
                waf_info = {}
            scan["waf"] = waf_info
            if waf_info.get("detected"):
                await log("WAF: {} ({}%) — strategy: {}".format(
                    waf_info["vendor"], waf_info["confidence"], waf_info["strategy"]), "warning")
                await broadcast({"type": "waf_detected", "scan_id": scan_id, "waf": waf_info})
                if "cloudflare" in str(waf_info.get("vendor", "")).lower():
                    scan["cloudflare_passive_fallback"] = True
                    scan["effective_scan_mode"] = "passive_only"
                    waf_info["strategy"] = "passive_only"
                    await log(
                        "Cloudflare detected — automatically switching this scan "
                        "to passive-only mode. HTTP-only scanners cannot bypass "
                        "JavaScript challenges safely.",
                        "warning",
                    )
                    await broadcast({
                        "type": "cloudflare_detected",
                        "scan_id": scan_id,
                        "target": target,
                        "waf": waf_info,
                        "passive_fallback": True,
                    })
            else:
                await log("WAF: None detected", "success")

        # PHASE 1.5c: API SCHEMA INGESTION
        await planner_checkpoint("API schema ingestion")
        await enforce_scan_control(scan_id)
        await resources.gate()
        await log("P1.5c: API SCHEMA INGESTION", "phase")
        known_swagger = [jf["file"] for jf in recon_data.get("js_findings", [])
                         if any(k in jf.get("file","").lower()
                                for k in ["swagger","openapi","api-docs"])
                         and scope_policy.validate_target(jf.get("file", ""), action="scan")[0]]
        empty_schema_data = {
                "openapi_endpoints": [],
                "graphql_endpoints": [],
                "graphql_schemas": [],
                "all_urls": [],
                "schemas_found": 0,
            }
        def schema_log(msg, level="info"):
            asyncio.create_task(log(msg, level))
        try:
            schema_data = (
                await ingest_schemas(
                    allowed_live_hosts,
                    known_swagger,
                    [],
                    schema_log,
                )
                if adaptive_plan.level != "LIGHT"
                or target_profile.api_heavy
                or target_profile.graphql_detected
                else empty_schema_data
            )
        except Exception as e:
            await log("Schema ingestion error: {}".format(e), "error")
            schema_data = empty_schema_data
        target_profile = refine_profile(target_profile, recon_data, schema_data)
        adaptive_plan = build_adaptive_plan(
            target_profile,
            scan.get("requested_scan_mode", ""),
        )
        scan["target_profile"] = target_profile.to_dict()
        scan["adaptive_plan"] = adaptive_plan.to_dict()
        scan["schema_data"] = schema_data
        schema_urls = scope_policy.filter_urls(schema_data.get("all_urls", []), action="scan")
        scan["schema"] = {
            "openapi_count": len(schema_data.get("openapi_endpoints", [])),
            "graphql_count": len(schema_data.get("graphql_endpoints", [])),
            "schemas_found": schema_data.get("schemas_found", 0),
            "injected_urls": len(schema_urls),
        }
        if schema_data.get("schemas_found", 0) > 0:
            await broadcast({"type": "schema_ingested", "scan_id": scan_id,
                             "data": scan["schema"]})
            await log("Schema: {} OpenAPI + {} GraphQL → {} URLs injected".format(
                len(schema_data.get("openapi_endpoints",[])),
                len(schema_data.get("graphql_endpoints",[])), len(schema_urls)), "success")
        _save_phase_checkpoint(scan_id, "recon")

        # PHASE 2: HUNT
        await planner_checkpoint("hunt")
        await enforce_scan_control(scan_id)
        await _save_scan_transition(scan_id, "hunt")
        await log("P2: HUNT", "phase")

        async def hunt_progress(phase, cur, total, label):
            scan["planner"] = planner.to_dict()
            await progress(phase, cur, total, label)

        live_finding_ids = set()

        async def hunt_request_event(event: dict):
            payload = dict(event or {})
            payload.setdefault("type", "request")
            payload["scan_id"] = scan_id
            if payload["type"] == "request":
                scan["requests_streamed"] = scan.get("requests_streamed", 0) + 1
                payload["request_number"] = scan["requests_streamed"]
            await broadcast(payload)

        async def hunt_finding_event(finding: dict):
            live = normalize_finding(finding, scan_id=scan_id)
            finding_id = live.get("id", "")
            if finding_id and finding_id in live_finding_ids:
                return
            if finding_id:
                live_finding_ids.add(finding_id)
            await broadcast({
                "type": "finding_live",
                "scan_id": scan_id,
                "data": live,
                "finding_count": len(live_finding_ids),
            })

        prioritized_urls = prioritize_urls(recon_data.get("urls", []), recon_data.get("live_hosts", []))
        scan["risk_prioritized_url_count"] = len(prioritized_urls)
        if (
            scan.get("cloudflare_passive_fallback")
            or scope_policy.config.passive_only_mode
            or not scope_policy.config.active_testing_enabled
        ):
            await log(
                "Active hunt skipped: Cloudflare passive fallback"
                if scan.get("cloudflare_passive_fallback")
                else "Active hunt skipped by ScopePolicy",
                "warning",
            )
            raw_findings = []
        else:
            try:
                raw_findings = await run_hunt(
                    prioritized_urls,
                    recon_data.get("live_hosts", []),
                    log, hunt_progress,
                    waf_info=waf_info, schema_urls=schema_urls,
                    graphql_schemas=schema_data.get("graphql_schemas", []),
                    schema_endpoints=schema_data.get("openapi_endpoints", []),
                    websocket_urls=recon_data.get("websocket_urls", []),
                    js_urls=recon_data.get("js_urls", []),
                    enabled_classes=adaptive_plan.enabled_modules,
                    max_urls=adaptive_plan.max_urls,
                    concurrency_override=adaptive_plan.concurrency,
                    request_timeout=adaptive_plan.request_timeout,
                    batch_size=adaptive_plan.request_batch_size,
                    resource_controller=resources,
                    scan_level=adaptive_plan.level,
                    planner=planner,
                    request_event_cb=hunt_request_event,
                    finding_event_cb=hunt_finding_event,
                )
            except Exception as e:
                await log("Hunt error: {}".format(e), "error")
                raw_findings = []
        raw_findings = normalize_findings(raw_findings, scan_id=scan_id)

        # POST-HUNT: offline business-logic candidate classification.
        # This phase analyzes only existing findings and discovered endpoint
        # metadata; it does not send requests.
        classification_recon = dict(recon_data)
        classification_recon["openapi_endpoints"] = schema_data.get(
            "openapi_endpoints", []
        )
        classification_recon["graphql_endpoints"] = schema_data.get(
            "graphql_endpoints", []
        )
        try:
            business_logic_candidates = normalize_findings(
                classify_business_logic_candidates(raw_findings, classification_recon),
                scan_id=scan_id,
            ) if adaptive_plan.run_business_logic else []
        except Exception as e:
            await log("Business logic classification error: {}".format(e), "error")
            business_logic_candidates = []
        raw_findings.extend(business_logic_candidates)
        scan["business_logic_candidates"] = business_logic_candidates
        await log(
            "Post-hunt business logic classifier: {} manual candidate(s)".format(
                len(business_logic_candidates)
            ),
            "success",
        )

        # Phase 2 supplement: bounded nuclei CVE/exposure/misconfiguration scan.
        await resources.gate()
        try:
            nuclei_findings = (
                await run_nuclei_scan(
                    recon_data.get("live_hosts", []),
                    scope_policy,
                    log,
                )
                if adaptive_plan.run_nuclei
                and not scan.get("cloudflare_passive_fallback")
                else []
            )
        except Exception as e:
            await log("Nuclei error: {}".format(e), "error")
            nuclei_findings = []
        nuclei_findings = normalize_findings(nuclei_findings, scan_id=scan_id)
        raw_findings.extend(nuclei_findings)
        scan["nuclei_findings"] = nuclei_findings
        _remember_hunt_outcomes(raw_findings, recon_data.get("tech_stack", []))
        if nuclei_findings:
            await log(
                "Nuclei supplement: {} finding(s) added before triage.".format(
                    len(nuclei_findings)
                ),
                "success",
            )

        for f in raw_findings:
            f["timestamp"] = datetime.utcnow().isoformat()
            findings_store.append(f)
            stats[f["severity"]] += 1; stats["total"] += 1
            swarm_write(
                "hunt-agent",
                "RAW_FINDING",
                f.get("affected_url") or f.get("url") or target,
                {
                    "finding_id": f.get("id", ""),
                    "vulnerability_class": f.get("vulnerability_class")
                    or f.get("vuln_type", ""),
                    "severity": f.get("severity", "INFO"),
                    "confidence": f.get("confidence", 0),
                },
                {
                    "CRITICAL": 1.0,
                    "HIGH": 0.85,
                    "MEDIUM": 0.6,
                    "LOW": 0.35,
                    "INFO": 0.15,
                }.get(str(f.get("severity", "INFO")).upper(), 0.3),
            )
            await broadcast({"type": "finding", "data": f})
        await broadcast({"type": "stats", "data": dict(stats)})
        scan["raw_findings"] = raw_findings
        await log("Hunt: {} raw findings | WAF blocks: {} | OOB payloads: {}".format(
            len(raw_findings), throttle._total_blocks, oob.payload_count), "success")
        _save_phase_checkpoint(scan_id, "hunt")

        # OOB POLL
        if oob_started:
            await enforce_scan_control(scan_id)
            await log("Polling OOB interactions...", "phase")
            try:
                oob_findings = await oob.poll_interactions(log, wait_secs=12)
            except Exception as e:
                await log("OOB polling error: {}".format(e), "error")
                oob_findings = []
            for f in oob_findings:
                f["id"]        = "OOB-{}-{}".format(int(time.time()*1000), len(findings_store))
                f["timestamp"] = datetime.utcnow().isoformat()
                f.setdefault("method", "GET")
                f.setdefault("triaged", False)
                f.setdefault("verdict", "PASS")
                f = normalize_finding(f, scan_id=scan_id)
                findings_store.append(f)
                stats[f["severity"]] += 1; stats["total"] += 1
                await broadcast({"type": "finding", "data": f})
            if oob_findings:
                await log("{} confirmed blind OOB finding(s)!".format(
                    len(oob_findings)), "success")

            # v3.4 Fix 5: Save OOB session to DB for offline resume-poll
            oob.save_session_to_db(scan_id)
            await log("[OOB] Session persisted — re-poll later with: "
                      "python3 resume_poll.py --scan-id {}".format(scan_id), "success")

            # v3.2: Register broadcast context then start background poller
            oob.register_background_context(scan_id, broadcast, scan)
            oob.start_background_poller(log)
            # NOTE: oob.stop() is intentionally NOT called here — the background
            # poller keeps the process alive. It stops itself after the window expires.

        # PHASE 3: TRIAGE
        await planner_checkpoint("triage")
        await enforce_scan_control(scan_id)
        await _save_scan_transition(scan_id, "triage")
        await log("P3: CoT TRIAGE", "phase")
        all_for_triage = (
            raw_findings
            + [f for f in findings_store if f.get("source","").startswith("js-")]
            + [f for f in findings_store if f.get("source") == "oob-interaction"]
        )
        seen_ids = set()
        unique_triage = [f for f in all_for_triage
                         if f["id"] not in seen_ids and not seen_ids.add(f["id"])]

        async def triage_progress(phase, cur, total, label):
            await progress("triage", cur, total, label)
            await broadcast({"type": "triage_update", "scan_id": scan_id,
                             "current": cur, "total": total, "label": label})

        reasoning_terms = (
            "idor", "bola", "auth", "authorization", "oauth", "jwt",
            "business logic", "privilege", "account takeover", "chain",
        )
        ai_available = await ai_router.has_available_provider()
        if not ai_available:
            ai_candidates = unique_triage
        elif adaptive_plan.level == "DEEP":
            ai_candidates = unique_triage
        else:
            ai_candidates = [
                finding for finding in unique_triage
                if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
                or any(
                    term in "{} {}".format(
                        finding.get("vuln_type", ""),
                        finding.get("title", ""),
                    ).lower()
                    for term in reasoning_terms
                )
            ]
        if ai_candidates:
            await resources.gate()
            try:
                ai_triaged, verdict_counts = await batch_triage(
                    ai_candidates, api_key, log, triage_progress
                )
            except Exception as e:
                await log("Triage error: {}".format(e), "error")
                ai_triaged = [
                    {
                        **finding,
                        "verdict": "NEEDS_MANUAL_REVIEW",
                        "triaged": False,
                        "triage": {
                            "verdict": "NEEDS_MANUAL_REVIEW",
                            "reason": "Triage phase failed",
                        },
                    }
                    for finding in ai_candidates
                ]
                verdict_counts = {"NEEDS_MANUAL_REVIEW": len(ai_triaged)}
            ai_map = {finding.get("id"): finding for finding in ai_triaged}
            triaged = [
                ai_map.get(finding.get("id"), {
                    **finding,
                    "verdict": finding.get("verdict", "DOWNGRADE"),
                })
                for finding in unique_triage
            ]
        else:
            triaged = [
                {**finding, "verdict": finding.get("verdict", "DOWNGRADE")}
                for finding in unique_triage
            ]
            verdict_counts = {"adaptive_no_ai_needed": len(triaged)}
        triaged = normalize_findings(triaged, scan_id=scan_id)
        triaged_findings = triaged
        scan["triaged_findings"] = triaged
        for finding in triaged:
            if finding.get("verdict") not in ("PASS", "DOWNGRADE", "CONFIRMED"):
                continue
            swarm_write(
                "validator",
                "VALIDATED_FINDING",
                finding.get("affected_url") or finding.get("url") or target,
                {
                    "finding_id": finding.get("id", ""),
                    "vulnerability_class": finding.get("vulnerability_class")
                    or finding.get("vuln_type", ""),
                    "severity": finding.get("severity", "INFO"),
                    "exploitability_status": finding.get(
                        "exploitability_status", ""
                    ),
                    "evidence_strength": finding.get("evidence_strength", ""),
                },
                1.0
                if finding.get("exploitability_status") == "confirmed"
                else 0.75,
            )
        triaged_map = {f["id"]: f for f in triaged}
        for i, f in enumerate(findings_store):
            if f["id"] in triaged_map:
                findings_store[i] = triaged_map[f["id"]]
        await broadcast({"type": "triage_complete", "scan_id": scan_id,
                         "verdicts": verdict_counts})
        await log("Triage: {}".format(
            " | ".join("{}: {}".format(k,v) for k,v in verdict_counts.items())), "success")
        _save_phase_checkpoint(scan_id, "triage")

        # PHASE 4: DEEP ANALYSIS
        await planner_checkpoint("deep analysis")
        await enforce_scan_control(scan_id)
        await _save_scan_transition(scan_id, "analysis")
        await log("P4: DEEP ANALYSIS", "phase")
        passable = [f for f in triaged if f.get("verdict") in ("PASS","DOWNGRADE")]
        swarm_frontier = swarm_blackboard.query(
            scan_id,
            TriggerPredicate(
                finding_types=("VALIDATED_FINDING",),
                minimum_pheromone=0.65,
                limit=100,
            ),
        )
        scan["swarm_frontier"] = swarm_frontier
        swarm_promoted_analysis = bool(swarm_frontier)
        if swarm_promoted_analysis and not adaptive_plan.run_deep_analysis:
            await log(
                "Swarm frontier promoted deep analysis for {} hot validated signal(s).".format(
                    len(swarm_frontier)
                ),
                "adaptive",
            )
        await resources.gate()
        try:
            analysis = (
                await run_deep_analysis(passable, recon_data, api_key)
                if adaptive_plan.run_deep_analysis or swarm_promoted_analysis
                else {
                    "chains": [],
                    "high_priority": passable[:10],
                    "adaptive_skip": (
                        "Deep AI analysis was not needed for the selected target profile."
                    ),
                }
            )
        except Exception as e:
            await log("Analysis error: {}".format(e), "error")
            analysis = {
                "chains": [],
                "high_priority": passable[:10],
                "analysis_error": str(e),
            }
        try:
            ato_recon = dict(recon_data)
            ato_recon["openapi_endpoints"] = schema_data.get("openapi_endpoints", [])
            ato_chains = detect_ato_chains(triaged, ato_recon)
            scan["ato_chains"] = ato_chains
            exploit_chains = build_exploit_chains(passable)
            generated_exploit_chains = analyze_exploit_chains(passable)
            for finding in triaged:
                finding.update(score_impact_finding(finding, exploit_chains))
            passable = [f for f in triaged if f.get("verdict") in ("PASS", "DOWNGRADE")]
            scan["triaged_findings"] = triaged
            scan["exploit_chains"] = exploit_chains
            scan["generated_exploit_chains"] = generated_exploit_chains
            attack_graph = build_attack_graph(passable, ato_chains).to_dict()
            attack_graph["exploit_chains"] = exploit_chains
            attack_graph["generated_exploit_chains"] = generated_exploit_chains
            coverage = compute_coverage(recon_data, passable, prioritized_urls[:200])
            coverage2 = compute_coverage_v2(
                scan_id,
                recon_data,
                passable,
                prioritized_urls[:200],
                scan.get("logs", []),
            )
            playbook = build_scan_playbook(
                recon_data,
                passable,
                coverage2,
                scan.get("planner", {}),
            )
            auth_coverage = analyze_auth_coverage(
                recon_data,
                auth_matrix.stats,
                passable,
                coverage2,
            )
        except Exception as e:
            await log("Coverage and attack graph error: {}".format(e), "error")
            ato_chains = []
            exploit_chains = {}
            generated_exploit_chains = []
            attack_graph = {
                "attack_paths": [],
                "path_count": 0,
                "exploit_chains": {},
                "generated_exploit_chains": [],
            }
            coverage = {"coverage_percent": 0}
            coverage2 = {"coverage_percent": 0}
            playbook = build_scan_playbook(recon_data, passable, coverage2, scan.get("planner", {}))
            auth_coverage = analyze_auth_coverage(recon_data, auth_matrix.stats, passable, coverage2)
        attack_graph_data = attack_graph
        coverage_data = coverage2
        analysis["attack_graph"] = attack_graph
        analysis["exploit_chains"] = exploit_chains
        analysis["generated_exploit_chains"] = generated_exploit_chains
        analysis["ato_chains"] = ato_chains
        analysis["coverage"] = coverage
        analysis["coverage_v2"] = coverage2
        analysis["playbook"] = playbook
        analysis["auth_coverage"] = auth_coverage
        for path in attack_graph.get("attack_paths", [])[:20]:
            swarm_write(
                "chain-builder",
                "EXPLOIT_CHAIN",
                target,
                {
                    "summary": path.get("summary", ""),
                    "score": path.get("score", 0),
                    "impact": path.get("impact", ""),
                    "chain_label": path.get("chain_label", ""),
                    "steps": path.get("steps", 0),
                },
                min(1.0, max(0.2, float(path.get("score", 0) or 0) / 10.0)),
            )
        scan["playbook"] = playbook
        scan["auth_coverage"] = auth_coverage
        scan["analysis"] = analysis
        scan["resource_control"] = resources.status()
        autopilot_state.output(scan_id, "analysis", "coverage_attack_graph", {
            "coverage_v2": coverage2,
            "attack_graph": attack_graph,
            "playbook": playbook,
            "auth_coverage": auth_coverage,
        })
        chains   = analysis.get("chains",        [])
        priority = analysis.get("high_priority", [])
        await broadcast({"type": "analysis_complete", "scan_id": scan_id,
                         "chains": chains, "high_priority": priority,
                         "ato_chains": ato_chains})
        await broadcast({"type": "attack_graph", "scan_id": scan_id, "data": attack_graph})
        await broadcast({"type": "coverage", "scan_id": scan_id, "data": coverage})
        await broadcast({"type": "coverage_v2", "scan_id": scan_id, "data": coverage2})
        await broadcast({"type": "playbook", "scan_id": scan_id, "data": playbook})
        await broadcast({"type": "auth_coverage", "scan_id": scan_id, "data": auth_coverage})
        await log("Analysis: {} LLM chains | {} graph paths | {}% coverage".format(
            len(chains), attack_graph.get("path_count", 0), coverage.get("coverage_percent", 0)), "success")
        _save_phase_checkpoint(scan_id, "analysis")

        # PHASE 5: REPORT
        await planner_checkpoint("reporting")
        await enforce_scan_control(scan_id)
        await _save_scan_transition(scan_id, "report")
        await log("P5: GENERATING REPORT", "phase")
        try:
            report_md = await generate_full_report(
                target, recon_data, triaged, analysis, api_key,
                scope=scope_policy.to_dict(),
                review_items=review_queue.get_all(scan_id, limit=500))
        except Exception as e:
            await log("Report generation error: {}".format(e), "error")
            report_md = (
                "# BurpOllama Partial Scan Report\n\n"
                "Target: {}\n\n"
                "Report generation failed, but the scan results remain available "
                "in the dashboard.\n\nError: {}\n"
            ).format(target, e)
        scan["report"] = report_md
        scan["platform_reports"] = {
            finding["id"]: {
                "hackerone": generate_h1_report(finding),
                "bugcrowd": generate_bugcrowd_report(finding),
            }
            for finding in triaged
            if finding.get("verdict") in ("PASS", "DOWNGRADE")
        }
        autopilot_state.output(scan_id, "reporter", "report", {"chars": len(report_md or "")})
        reportable = len([f for f in triaged if f.get("verdict") in ("PASS","DOWNGRADE")])
        await broadcast({"type": "report_ready", "scan_id": scan_id,
                         "reportable": reportable})
        await log("Report ready: {} reportable findings".format(reportable), "success")
        _save_phase_checkpoint(scan_id, "report")

        # PHASE 6: ANALYST INTELLIGENCE
        await planner_checkpoint("analyst intelligence")
        await enforce_scan_control(scan_id)
        await resources.gate()
        await _save_scan_transition(scan_id, "intelligence")
        await log("P6: ANALYST INTELLIGENCE BRIEFING", "phase")
        try:
            intelligence = (
                _fallback_scan_intelligence(
                    triaged,
                    recon_data,
                    attack_graph,
                    coverage2,
                )
                if adaptive_plan.level == "LIGHT" or not triaged
                else await generate_scan_intelligence(
                    scan_id,
                    triaged,
                    recon_data,
                    attack_graph,
                    coverage2,
                    api_key,
                )
            )
        except Exception as e:
            await log("Intelligence error: {}".format(e), "error")
            intelligence = _fallback_scan_intelligence(
                triaged,
                recon_data,
                attack_graph,
                coverage2,
            )
            intelligence["generation_error"] = str(e)
        scan["intelligence"] = intelligence
        planner.complete()
        scan["planner"] = planner.to_dict()
        scan["planner_summary"] = planner.summarize_progress()
        autopilot_state.output(
            scan_id,
            "analyst",
            "intelligence_briefing",
            intelligence,
        )
        await broadcast({
            "type": "intelligence_ready",
            "scan_id": scan_id,
            "data": intelligence,
        })
        await log(
            "Intelligence briefing ready: {} manual target(s)".format(
                len(intelligence.get("top_manual_targets", []))
            ),
            "success",
        )
        _save_phase_checkpoint(scan_id, "intelligence")
        scan.update({"status": "complete", "phase": "complete",
                     "finished": datetime.utcnow().isoformat()})
        autopilot_state.update_run(scan_id, status="completed", phase="completed",
                                   checkpoint={"finished": scan["finished"]}, finished=True)
        autopilot_state.upsert_task(scan_id, "full_pipeline", "completed")
        event_store.append(scan_id, "scan.complete", {
            "reportable": reportable,
            "coverage": scan.get("analysis", {}).get("coverage", {}),
        })
        swarm_write(
            "report-writer",
            "CAMPAIGN_COMPLETE",
            target,
            {
                "reportable": reportable,
                "coverage_percent": coverage2.get("coverage_percent", 0),
                "attack_paths": attack_graph.get("path_count", 0),
            },
            1.0,
        )
        scan["swarm"] = swarm_blackboard.status(scan_id)
        if task_id:
            scheduler.complete(task_id)
        await broadcast({"type": "scan_complete", "scan_id": scan_id,
                         "stats": dict(stats), "reportable": reportable})
        await log("SCAN COMPLETE", "success")

    except ScanStopped as e:
        swarm_write(
            "autopilot",
            "AGENT_ERROR",
            target,
            {"status": "stopped", "reason": str(e)},
            0.8,
        )
        scan["planner"] = planner.to_dict()
        scan["planner_summary"] = planner.summarize_progress()
        scan.update({"status": "stopped", "phase": "stopped", "error": str(e)})
        autopilot_state.update_run(scan_id, status="stopped", phase="stopped",
                                   checkpoint={"error": str(e)}, finished=True)
        autopilot_state.upsert_task(scan_id, "full_pipeline", "stopped", error=str(e))
        await log("Scan stopped: {}".format(e), "warning")
        await broadcast({"type": "scan_stopped", "scan_id": scan_id, "reason": str(e)})
        event_store.append(scan_id, "scan.stopped", {"reason": str(e)})
    except Exception as e:
        swarm_write(
            "autopilot",
            "AGENT_ERROR",
            target,
            {"status": "failed", "reason": str(e)},
            1.0,
        )
        scan["planner"] = planner.to_dict()
        scan["planner_summary"] = planner.summarize_progress()
        scan.update({"status": "failed", "phase": "failed", "error": str(e)})
        autopilot_state.update_run(scan_id, status="failed", phase=scan.get("phase", "error"),
                                   checkpoint={"error": str(e)})
        autopilot_state.upsert_task(scan_id, "full_pipeline", "failed", error=str(e))
        event_store.append(scan_id, "scan.error", {"error": str(e)})
        if task_id:
            scheduler.fail(task_id, str(e))
        await log("Pipeline error: {}".format(e), "error")
        await broadcast({"type": "scan_error", "scan_id": scan_id, "error": str(e)})
        # v3.4: Always stop OOB subprocess on error to prevent process leak
        try:
            if oob._started:
                await oob.stop()
        except Exception:
            pass


async def _resume_pipeline_from_checkpoint(
    scan_id: str,
    target: str,
    api_key: str,
    completed_phases: set[str],
):
    """Continue only phases that do not have a durable completion event."""
    scan = scans[scan_id]
    scan["status"] = "running"
    scan["control"] = "run"
    scan["_checkpoint_resume_running"] = True
    durable_run = autopilot_state.get_run(scan_id) or {}
    planner = WorkingMemory.from_dict(
        scan.get("planner")
        or durable_run.get("checkpoint", {}).get("planner")
        or {}
    )

    def persist_planner():
        scan["planner"] = planner.to_dict()
        scan["planner_summary"] = planner.summarize_progress()
        autopilot_state.update_run(
            scan_id,
            checkpoint={"planner": scan["planner"]},
        )

    async def log(msg, level="info"):
        await log_broadcast(scan_id, msg, level)

    async def progress(phase, current, total, label=""):
        scan["phase"] = phase
        scan["progress"] = {
            "current": current,
            "total": total,
            "label": label,
        }
        await broadcast({
            "type": "progress",
            "scan_id": scan_id,
            "phase": phase,
            "current": current,
            "total": total,
            "label": label,
        })

    try:
        event_store.append(
            scan_id,
            "scan.checkpoint_resume_started",
            {"completed_phases": sorted(completed_phases)},
        )
        await log(
            "Resuming from checkpoint; completed phases: {}".format(
                ", ".join(sorted(completed_phases)) or "none"
            ),
            "phase",
        )

        if "recon" not in completed_phases:
            # No safe artifact boundary exists before recon completion.
            scan.pop("_checkpoint_resume_running", None)
            await run_pipeline(scan_id, target, api_key)
            return

        recon_data = scan.get("recon") or {}
        schema_data = scan.get("schema_data") or {}
        waf_info = scan.get("waf") or {}
        if not recon_data:
            raise RuntimeError("Recon checkpoint is missing recon artifacts.")
        if scan.get("adaptive_plan"):
            adaptive_plan = AdaptivePlan(**scan["adaptive_plan"])
        else:
            resume_profile = refine_profile(
                TargetProfile(target=target),
                recon_data,
                schema_data,
            )
            adaptive_plan = build_adaptive_plan(
                resume_profile,
                scan.get("requested_scan_mode", ""),
            )
            if recon_data.get("websocket_urls"):
                adaptive_plan.enabled_modules = sorted(set(
                    adaptive_plan.enabled_modules + ["WebSocket Active Security"]
                ))
            if recon_data.get("js_urls"):
                adaptive_plan.enabled_modules = sorted(set(
                    adaptive_plan.enabled_modules + ["Browser Storage Security"]
                ))
            scan["target_profile"] = resume_profile.to_dict()
            scan["adaptive_plan"] = adaptive_plan.to_dict()
        resources = ResourceController(
            cpu_limit_percent=adaptive_plan.cpu_limit_percent
        )
        prioritized_urls = prioritize_urls(
            recon_data.get("urls", []),
            recon_data.get("live_hosts", []),
        )
        schema_urls = scope_policy.filter_urls(
            schema_data.get("all_urls", []),
            action="scan",
        )

        if "hunt" not in completed_phases:
            await enforce_scan_control(scan_id)
            await _save_scan_transition(scan_id, "hunt")
            await log("P2: HUNT (checkpoint resume)", "phase")

            async def hunt_progress(phase, cur, total, label):
                persist_planner()
                await progress(phase, cur, total, label)

            if scope_policy.config.passive_only_mode or not scope_policy.config.active_testing_enabled:
                raw_findings = []
            else:
                raw_findings = await run_hunt(
                    prioritized_urls,
                    recon_data.get("live_hosts", []),
                    log,
                    hunt_progress,
                    waf_info=waf_info,
                    schema_urls=schema_urls,
                    graphql_schemas=schema_data.get("graphql_schemas", []),
                    schema_endpoints=schema_data.get("openapi_endpoints", []),
                    websocket_urls=recon_data.get("websocket_urls", []),
                    js_urls=recon_data.get("js_urls", []),
                    enabled_classes=adaptive_plan.enabled_modules,
                    max_urls=adaptive_plan.max_urls,
                    concurrency_override=adaptive_plan.concurrency,
                    request_timeout=adaptive_plan.request_timeout,
                    batch_size=adaptive_plan.request_batch_size,
                    resource_controller=resources,
                    scan_level=adaptive_plan.level,
                    planner=planner,
                )
            raw_findings = normalize_findings(raw_findings, scan_id=scan_id)
            classification_recon = dict(recon_data)
            classification_recon["openapi_endpoints"] = schema_data.get(
                "openapi_endpoints", []
            )
            classification_recon["graphql_endpoints"] = schema_data.get(
                "graphql_endpoints", []
            )
            if adaptive_plan.run_business_logic:
                raw_findings.extend(normalize_findings(
                    classify_business_logic_candidates(
                        raw_findings,
                        classification_recon,
                    ),
                    scan_id=scan_id,
                ))
            if adaptive_plan.run_nuclei:
                await resources.gate()
                raw_findings.extend(normalize_findings(
                    await run_nuclei_scan(
                        recon_data.get("live_hosts", []),
                        scope_policy,
                        log,
                    ),
                    scan_id=scan_id,
                ))
            scan["raw_findings"] = raw_findings
            _remember_hunt_outcomes(raw_findings, recon_data.get("tech_stack", []))
            existing_ids = {
                finding.get("id")
                for finding in findings_store
                if finding.get("scan_id") == scan_id
            }
            for finding in raw_findings:
                if finding.get("id") in existing_ids:
                    continue
                finding["timestamp"] = datetime.utcnow().isoformat()
                findings_store.append(finding)
                stats[finding["severity"]] += 1
                stats["total"] += 1
                await broadcast({"type": "finding", "data": finding})
            _save_phase_checkpoint(scan_id, "hunt")
            persist_planner()
            completed_phases.add("hunt")
        else:
            raw_findings = normalize_findings(
                scan.get("raw_findings") or [],
                scan_id=scan_id,
            )

        if "triage" not in completed_phases:
            await enforce_scan_control(scan_id)
            await _save_scan_transition(scan_id, "triage")
            await log("P3: CoT TRIAGE (checkpoint resume)", "phase")

            async def triage_progress(phase, cur, total, label):
                await progress("triage", cur, total, label)

            ai_available = await ai_router.has_available_provider()
            if not ai_available:
                resume_ai_candidates = raw_findings
            elif adaptive_plan.level == "DEEP":
                resume_ai_candidates = raw_findings
            else:
                resume_ai_candidates = [
                    finding for finding in raw_findings
                    if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
                    or any(
                        term in "{} {}".format(
                            finding.get("vuln_type", ""),
                            finding.get("title", ""),
                        ).lower()
                        for term in (
                            "idor", "bola", "auth", "authorization", "oauth",
                            "jwt", "business logic", "privilege",
                            "account takeover", "chain",
                        )
                    )
                ]
            if resume_ai_candidates:
                await resources.gate()
                ai_triaged, verdict_counts = await batch_triage(
                    resume_ai_candidates,
                    api_key,
                    log,
                    triage_progress,
                )
                resume_ai_map = {
                    finding.get("id"): finding for finding in ai_triaged
                }
                triaged = [
                    resume_ai_map.get(finding.get("id"), {
                        **finding,
                        "verdict": finding.get("verdict", "DOWNGRADE"),
                    })
                    for finding in raw_findings
                ]
            else:
                triaged = [
                    {**finding, "verdict": finding.get("verdict", "DOWNGRADE")}
                    for finding in raw_findings
                ]
                verdict_counts = {"adaptive_no_ai_needed": len(triaged)}
            triaged = normalize_findings(triaged, scan_id=scan_id)
            scan["triaged_findings"] = triaged
            await broadcast({
                "type": "triage_complete",
                "scan_id": scan_id,
                "verdicts": verdict_counts,
            })
            _save_phase_checkpoint(scan_id, "triage")
            planner.record_step("Triage", "completed", len(triaged))
            persist_planner()
            completed_phases.add("triage")
        else:
            triaged = normalize_findings(
                scan.get("triaged_findings") or raw_findings,
                scan_id=scan_id,
            )

        if "analysis" not in completed_phases:
            await enforce_scan_control(scan_id)
            await _save_scan_transition(scan_id, "analysis")
            await log("P4: DEEP ANALYSIS (checkpoint resume)", "phase")
            passable = [
                finding for finding in triaged
                if finding.get("verdict") in ("PASS", "DOWNGRADE")
            ]
            await resources.gate()
            analysis = (
                await run_deep_analysis(
                    passable,
                    recon_data,
                    api_key,
                )
                if adaptive_plan.run_deep_analysis
                else {
                    "chains": [],
                    "high_priority": passable[:10],
                    "adaptive_skip": (
                        "Deep AI analysis was not needed for the selected target profile."
                    ),
                }
            )
            ato_recon = dict(recon_data)
            ato_recon["openapi_endpoints"] = schema_data.get("openapi_endpoints", [])
            ato_chains = detect_ato_chains(triaged, ato_recon)
            scan["ato_chains"] = ato_chains
            exploit_chains = build_exploit_chains(passable)
            generated_exploit_chains = analyze_exploit_chains(passable)
            for finding in triaged:
                finding.update(score_impact_finding(finding, exploit_chains))
            passable = [
                f for f in triaged if f.get("verdict") in ("PASS", "DOWNGRADE")
            ]
            scan["triaged_findings"] = triaged
            scan["exploit_chains"] = exploit_chains
            scan["generated_exploit_chains"] = generated_exploit_chains
            attack_graph = build_attack_graph(passable, ato_chains).to_dict()
            attack_graph["exploit_chains"] = exploit_chains
            attack_graph["generated_exploit_chains"] = generated_exploit_chains
            coverage = compute_coverage(
                recon_data,
                passable,
                prioritized_urls[:200],
            )
            coverage2 = compute_coverage_v2(
                scan_id,
                recon_data,
                passable,
                prioritized_urls[:200],
                scan.get("logs", []),
            )
            analysis["attack_graph"] = attack_graph
            analysis["exploit_chains"] = exploit_chains
            analysis["generated_exploit_chains"] = generated_exploit_chains
            analysis["ato_chains"] = ato_chains
            analysis["coverage"] = coverage
            analysis["coverage_v2"] = coverage2
            playbook = build_scan_playbook(
                recon_data,
                passable,
                coverage2,
                scan.get("planner", {}),
            )
            auth_coverage = analyze_auth_coverage(
                recon_data,
                auth_matrix.stats,
                passable,
                coverage2,
            )
            analysis["playbook"] = playbook
            analysis["auth_coverage"] = auth_coverage
            scan["playbook"] = playbook
            scan["auth_coverage"] = auth_coverage
            scan["analysis"] = analysis
            await broadcast({
                "type": "analysis_complete",
                "scan_id": scan_id,
                "chains": analysis.get("chains", []),
                "high_priority": analysis.get("high_priority", []),
                "ato_chains": ato_chains,
            })
            await broadcast({"type": "playbook", "scan_id": scan_id, "data": playbook})
            await broadcast({"type": "auth_coverage", "scan_id": scan_id, "data": auth_coverage})
            _save_phase_checkpoint(scan_id, "analysis")
            planner.record_step(
                "Deep Analysis",
                "completed",
                len(analysis.get("high_priority", [])),
            )
            persist_planner()
            completed_phases.add("analysis")
        else:
            analysis = scan.get("analysis") or {}

        if "report" not in completed_phases:
            await enforce_scan_control(scan_id)
            await _save_scan_transition(scan_id, "report")
            await log("P5: GENERATING REPORT (checkpoint resume)", "phase")
            report_md = await generate_full_report(
                target,
                recon_data,
                triaged,
                analysis,
                api_key,
                scope=scope_policy.to_dict(),
                review_items=review_queue.get_all(scan_id, limit=500),
            )
            scan["report"] = report_md
            scan["platform_reports"] = {
                finding["id"]: {
                    "hackerone": generate_h1_report(finding),
                    "bugcrowd": generate_bugcrowd_report(finding),
                }
                for finding in triaged
                if finding.get("verdict") in ("PASS", "DOWNGRADE")
            }
            reportable = len([
                finding for finding in triaged
                if finding.get("verdict") in ("PASS", "DOWNGRADE")
            ])
            await broadcast({
                "type": "report_ready",
                "scan_id": scan_id,
                "reportable": reportable,
            })
            _save_phase_checkpoint(scan_id, "report")
            planner.record_step("Reporting", "completed", reportable)
            persist_planner()
            completed_phases.add("report")
        else:
            reportable = len([
                finding for finding in triaged
                if finding.get("verdict") in ("PASS", "DOWNGRADE")
            ])

        if "intelligence" not in completed_phases:
            await enforce_scan_control(scan_id)
            await resources.gate()
            await _save_scan_transition(scan_id, "intelligence")
            await log("P6: ANALYST INTELLIGENCE BRIEFING (checkpoint resume)", "phase")
            intelligence = (
                _fallback_scan_intelligence(
                    triaged,
                    recon_data,
                    analysis.get("attack_graph", {}),
                    analysis.get("coverage_v2") or analysis.get("coverage") or {},
                )
                if adaptive_plan.level == "LIGHT" or not triaged
                else await generate_scan_intelligence(
                    scan_id,
                    triaged,
                    recon_data,
                    analysis.get("attack_graph", {}),
                    analysis.get("coverage_v2") or analysis.get("coverage") or {},
                    api_key,
                )
            )
            scan["intelligence"] = intelligence
            autopilot_state.output(
                scan_id,
                "analyst",
                "intelligence_briefing",
                intelligence,
            )
            await broadcast({
                "type": "intelligence_ready",
                "scan_id": scan_id,
                "data": intelligence,
            })
            _save_phase_checkpoint(scan_id, "intelligence")
            planner.record_step(
                "Analyst Intelligence",
                "completed",
                len(intelligence.get("top_manual_targets", [])),
            )
            persist_planner()
            completed_phases.add("intelligence")

        planner.complete()
        persist_planner()
        scan.update({
            "status": "complete",
            "phase": "complete",
            "finished": datetime.utcnow().isoformat(),
        })
        scan.pop("_checkpoint_resume_running", None)
        event_store.append(
            scan_id,
            "scan.complete",
            {
                "reportable": reportable,
                "resumed_from_checkpoint": True,
            },
        )
        await broadcast({
            "type": "scan_complete",
            "scan_id": scan_id,
            "stats": dict(stats),
            "reportable": reportable,
        })
        await log("CHECKPOINT RESUME COMPLETE", "success")
    except Exception as exc:
        scan.pop("_checkpoint_resume_running", None)
        scan.update({
            "status": "error",
            "error": str(exc),
        })
        event_store.append(
            scan_id,
            "scan.checkpoint_resume_error",
            {"error": str(exc), "phase": scan.get("phase", "")},
        )
        await log("Checkpoint resume error: {}".format(exc), "error")
        await broadcast({
            "type": "scan_error",
            "scan_id": scan_id,
            "error": str(exc),
        })


# ── App lifespan ──────────────────────────────────────────────────────────────
async def _show_startup_banner():
    global STARTUP_TIME, _startup_banner_printed
    if _startup_banner_printed:
        return
    STARTUP_TIME = datetime.utcnow().isoformat() + "Z"
    _startup_banner_printed = True
    cloud_enabled = os.getenv("CLOUD_AI_ENABLED", "0") == "1"
    ai_privacy_guard.update({"cloud_ai_enabled": cloud_enabled}, persist=False)
    scope_policy.update({"cloud_ai_enabled": cloud_enabled}, persist=False)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    print("")
    print("╔══════════════════════════════════════════╗")
    print("║      BurpOllama is running               ║")
    print("╠══════════════════════════════════════════╣")
    print("║  Dashboard: http://127.0.0.1:8888/ui     ║")
    print("║  Press Ctrl+C to stop                    ║")
    print("╚══════════════════════════════════════════╝")
    print("")


async def _launch_fresh_scope_scan(record: dict, target: str) -> Optional[str]:
    """Launch a feed-discovered target only after both authorization gates pass."""
    if not scope_policy.config.allowed_domains:
        return None
    ok, _ = scope_policy.validate_target(target, action="scan")
    if not ok:
        return None
    scan_id = str(uuid.uuid4())[:12]
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "queued",
        "phase": "queued",
        "control": "run",
        "requested_scan_mode": scope_policy.config.scan_mode,
        "authorization_warning": "",
        "started": datetime.utcnow().isoformat(),
        "logs": [],
        "fresh_scope_source": {
            "platform": record.get("platform", ""),
            "program_id": record.get("program_id", ""),
            "program_name": record.get("program_name", ""),
            "program_url": record.get("program_url", ""),
            "asset": record.get("asset", ""),
            "discovered_at": datetime.utcnow().isoformat(),
        },
    }
    resume_token = autopilot_state.create_run(
        scan_id, target, status="queued", phase="queued"
    )
    task_id = scheduler.enqueue(
        scan_id,
        "fresh_scope_pipeline",
        {
            "target": target,
            "platform": record.get("platform", ""),
            "program_id": record.get("program_id", ""),
        },
        priority=20,
    )
    scans[scan_id]["scheduler_task_id"] = task_id
    scans[scan_id]["autopilot_resume_token"] = resume_token
    autopilot_state.upsert_task(
        scan_id,
        "fresh_scope_pipeline",
        "queued",
        {"scheduler_task_id": task_id},
    )
    event_store.audit(
        "fresh-scope-agent",
        "scan.start",
        scan_id,
        scans[scan_id]["fresh_scope_source"],
    )
    asyncio.create_task(run_pipeline(scan_id, target, _gc.GEMINI_API_KEY))
    await broadcast(
        {
            "type": "fresh_scope_scan_started",
            "scan_id": scan_id,
            "target": target,
            "program": record.get("program_name", ""),
        }
    )
    return scan_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    workers = [asyncio.create_task(burp_worker()) for _ in range(3)]
    fresh_scope_task = asyncio.create_task(
        fresh_scope_hunter.run_forever(_launch_fresh_scope_scan)
    )
    await _show_startup_banner()
    yield
    fresh_scope_task.cancel()
    for w in workers: w.cancel()

app = FastAPI(title="BurpOllama", version="3.1.0", lifespan=lifespan)


@app.on_event("startup")
async def startup_event():
    await _show_startup_banner()


app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def observability_middleware(request, call_next):
    start = time.monotonic()
    try:
        response = await call_next(request)
        metrics.inc("http.requests", method=request.method, path=request.url.path, status=response.status_code)
        return response
    finally:
        metrics.observe("http.request_seconds", time.monotonic() - start,
                        method=request.method, path=request.url.path)

# ── Routes ────────────────────────────────────────────────────────────────────
@app.post("/config")
async def set_config(cfg: dict):
    """Validate and persist project settings to .env from the web UI."""
    if "gemini_api_key" in cfg and "GEMINI_API_KEY" not in cfg:
        cfg["GEMINI_API_KEY"] = cfg.pop("gemini_api_key")
    try:
        result = save_settings(cfg)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    set_api_key(os.getenv("GEMINI_API_KEY", ""))
    ai_router.configure_key("openai", os.getenv("OPENAI_API_KEY", ""))
    ai_router.configure_key("anthropic", os.getenv("ANTHROPIC_API_KEY", ""))
    ai_router.reload_from_env()
    cloud_enabled = os.getenv("CLOUD_AI_ENABLED", "0") == "1"
    ai_privacy_guard.update({"cloud_ai_enabled": cloud_enabled}, persist=False)
    scope_policy.update({"cloud_ai_enabled": cloud_enabled}, persist=False)
    event_store.audit(
        "local-user",
        "config.saved",
        ".env",
        {"keys_updated": sorted(key for key in cfg if key in result["settings"])},
    )
    return {
        **result,
        "saved": True,
        "ai_router": ai_router.status(),
        "restart_recommended": any(
            key in cfg
            for key in ("BURPOLLAMA_DATABASE_URL", "BURPOLLAMA_RETENTION_DAYS")
        ),
    }

@app.get("/config")
async def get_config():
    settings = public_settings()
    availability = await ai_router.availability()
    return {
        **settings,
        "key_status": "set" if availability["triage_capable"] else "not set",
        "model": availability["active_model"],
        "active_provider": availability["active_provider"],
        "ai_router": ai_router.status(),
    }


async def _ollama_model_status() -> dict:
    required = [
        os.getenv("OLLAMA_FAST_MODEL", "mistral"),
        os.getenv("OLLAMA_REASONING_MODEL", "llama3.1:8b"),
    ]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get("http://127.0.0.1:11434/api/tags")
            response.raise_for_status()
            payload = response.json()
        installed = [
            str(model.get("name") or model.get("model") or "")
            for model in payload.get("models", [])
        ]
        installed_set = set(installed)
        installed_bases = {name.split(":", 1)[0] for name in installed}

        def model_is_installed(model: str) -> bool:
            if ":" in model:
                return model in installed_set
            return model in installed_set or model in installed_bases

        missing = [model for model in required if not model_is_installed(model)]
        mistral_ready = model_is_installed("mistral")
        llama_ready = any(
            name.split(":", 1)[0].startswith("llama")
            for name in installed
        )
        return {
            "available": True,
            "installed": installed,
            "required": required,
            "missing": missing,
            "ollama_running": True,
            "models_available": installed,
            "mistral_ready": mistral_ready,
            "llama_ready": llama_ready,
            "recommended_model": (
                "mistral" if mistral_ready
                else "llama3.1" if llama_ready
                else None
            ),
        }
    except Exception as exc:
        return {
            "available": False,
            "installed": [],
            "required": required,
            "missing": required,
            "ollama_running": False,
            "models_available": [],
            "mistral_ready": False,
            "llama_ready": False,
            "recommended_model": None,
            "error": str(exc),
        }


@app.get("/ollama/status")
async def get_ollama_status():
    status = await _ollama_model_status()
    return {
        "ollama_running": status["ollama_running"],
        "models_available": status["models_available"],
        "mistral_ready": status["mistral_ready"],
        "llama_ready": status["llama_ready"],
        "recommended_model": status["recommended_model"],
    }


@app.get("/ollama/models")
async def get_ollama_models():
    return await _ollama_model_status()


@app.post("/ollama/pull")
async def pull_ollama_model(payload: dict):
    model = str(payload.get("model", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9._:/-]+", model):
        raise HTTPException(422, "Enter a valid Ollama model name.")
    try:
        await asyncio.create_subprocess_exec(
            "ollama",
            "pull",
            model,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return {"started": True, "model": model}
    except FileNotFoundError as exc:
        raise HTTPException(503, "Ollama is not installed or is not on PATH.") from exc
    except Exception as exc:
        raise HTTPException(503, "Ollama could not start pulling {}: {}".format(model, exc)) from exc


@app.post("/ai/providers/test")
async def test_ai_providers():
    checks: list[dict] = []
    ollama = await _ollama_model_status()
    checks.append({
        "provider": "Ollama",
        "ok": ollama.get("available", False),
        "detail": "Local Ollama is reachable." if ollama.get("available") else "Start Ollama, then try again.",
    })
    tests = [
        (
            "Gemini",
            os.getenv("GEMINI_API_KEY", ""),
            "https://generativelanguage.googleapis.com/v1beta/models",
            lambda key: {"key": key},
            {},
        ),
        (
            "OpenAI",
            os.getenv("OPENAI_API_KEY", ""),
            "https://api.openai.com/v1/models",
            lambda key: {},
            {"Authorization": "Bearer {}"},
        ),
        (
            "Anthropic",
            os.getenv("ANTHROPIC_API_KEY", ""),
            "https://api.anthropic.com/v1/models",
            lambda key: {},
            {"x-api-key": "{}", "anthropic-version": "2023-06-01"},
        ),
    ]
    async with httpx.AsyncClient(timeout=8.0) as client:
        for name, key, url, params_factory, header_templates in tests:
            if not key:
                checks.append({"provider": name, "ok": False, "configured": False, "detail": "No API key saved."})
                continue
            headers = {
                header: template.format(key)
                for header, template in header_templates.items()
            }
            try:
                response = await client.get(url, params=params_factory(key), headers=headers)
                ok = response.status_code < 400
                checks.append({
                    "provider": name,
                    "ok": ok,
                    "configured": True,
                    "detail": "Connection succeeded." if ok else "Provider returned HTTP {}.".format(response.status_code),
                })
            except Exception as exc:
                checks.append({"provider": name, "ok": False, "configured": True, "detail": str(exc)})
    return {"providers": checks}

@app.post("/config/sessions")
async def set_sessions(cfg: SessionConfig):
    """Configure dual-session authorization matrix."""
    try:
        auth_matrix.configure(
            session_a_cookie=cfg.session_a_cookie or "",
            session_a_token=cfg.session_a_token or "",
            session_b_cookie=cfg.session_b_cookie or "",
            session_b_token=cfg.session_b_token or "",
            session_a_role=cfg.session_a_role or "Attacker / lower privilege",
            session_b_role=cfg.session_b_role or "Victim / higher privilege",
            session_a_headers=cfg.session_a_headers,
            session_b_headers=cfg.session_b_headers,
            session_a_expires_at=cfg.session_a_expires_at,
            session_b_expires_at=cfg.session_b_expires_at,
            health_check_endpoint=cfg.health_check_endpoint or "",
            allow_mutations=cfg.allow_mutations,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    event_store.audit(
        "local-user",
        "sessions.configure",
        "dual-session-matrix",
        auth_matrix.stats,
    )
    return auth_matrix.stats

@app.get("/config/sessions")
async def get_sessions():
    return auth_matrix.stats

@app.get("/config/oob")
async def get_oob_status():
    return {
        "available":    oob.available,
        "domain":       oob.domain,
        "payload_count":oob.payload_count,
    }


@app.post("/scan")
async def start_scan(req: ScanRequest):
    if not req.authorization_confirmed:
        raise HTTPException(
            403,
            "Confirm that you own the target or have written permission to test it.",
        )
    requested_scan_mode = ""
    if req.scan_mode:
        scan_mode = scope_policy.normalize_scan_mode_label(req.scan_mode)
        scope_policy.update({"scan_mode": scan_mode})
        requested_scan_mode = scan_mode
    key = req.api_key or _gc.GEMINI_API_KEY
    ok, reason = scope_policy.validate_target(req.target, action="scan")
    if not ok:
        raise HTTPException(403, reason)
    authorization_warning = (
        "Make sure you have written authorization to test this target."
        if not scope_policy.config.allowed_domains
        else ""
    )
    if req.api_key:
        set_api_key(req.api_key)
    scan_id  = str(uuid.uuid4())[:12]
    scans[scan_id] = {
        "id":scan_id,"target":req.target,
        "status":"queued","phase":"queued",
        "control":"run",
        "requested_scan_mode": requested_scan_mode,
        "authorization_warning": authorization_warning,
        "started":datetime.utcnow().isoformat(),"logs":[],
    }
    resume_token = autopilot_state.create_run(scan_id, req.target, status="queued", phase="queued")
    task_id = scheduler.enqueue(scan_id, "full_pipeline", {"target": req.target}, priority=10)
    scans[scan_id]["scheduler_task_id"] = task_id
    scans[scan_id]["autopilot_resume_token"] = resume_token
    autopilot_state.upsert_task(scan_id, "full_pipeline", "queued", {"scheduler_task_id": task_id})
    event_store.audit("local-user", "scan.start", scan_id, {"target": req.target})
    asyncio.create_task(run_pipeline(scan_id, req.target, key))
    return {
        "scan_id": scan_id,
        "target": req.target,
        "status": "started",
        "resume_token": resume_token,
        "warning": authorization_warning,
    }

@app.post("/autopilot/start")
async def start_autopilot(req: ScanRequest):
    return await start_scan(req)

@app.post("/autopilot/resume")
async def resume_autopilot(req: AutopilotResumeRequest):
    stored = autopilot_state.get_run(req.scan_id)
    if not stored:
        raise HTTPException(404, "Autopilot run not found")
    if req.resume_token and req.resume_token != stored.get("resume_token"):
        raise HTTPException(403, "Invalid resume token")
    if req.scan_id in scans:
        scans[req.scan_id]["control"] = "run"
        scans[req.scan_id]["status"] = "running"
        autopilot_state.update_run(req.scan_id, status="running", phase=scans[req.scan_id].get("phase", "queued"))
        await broadcast({"type": "scan_resumed", "scan_id": req.scan_id})
        return {"resumed": True, "scan_id": req.scan_id, "mode": "in_memory"}
    scans[req.scan_id] = {
        "id": req.scan_id,
        "target": stored.get("target", ""),
        "status": "queued",
        "phase": stored.get("phase", "queued"),
        "control": "run",
        "started": stored.get("created_at", datetime.utcnow().isoformat()),
        "logs": [],
        "autopilot_resume_token": stored.get("resume_token"),
    }
    key = _gc.GEMINI_API_KEY
    task_id = scheduler.enqueue(req.scan_id, "full_pipeline_resume", {"target": stored.get("target", "")}, priority=5)
    scans[req.scan_id]["scheduler_task_id"] = task_id
    autopilot_state.update_run(req.scan_id, status="queued", phase=scans[req.scan_id].get("phase", "queued"),
                               checkpoint={"resumed_from_disk": True, "scheduler_task_id": task_id})
    autopilot_state.upsert_task(req.scan_id, "full_pipeline_resume", "queued", {"scheduler_task_id": task_id})
    asyncio.create_task(run_pipeline(req.scan_id, stored.get("target", ""), key))
    return {"resumed": True, "scan_id": req.scan_id, "mode": "durable_restart", "task_id": task_id}

@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    s = dict(scans[scan_id])
    s.pop("report",None); s.pop("raw_findings",None)
    return s

@app.get("/scan/{scan_id}/report")
async def get_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    report = scans[scan_id].get("report","")
    if not report: raise HTTPException(404,"Report not ready yet")
    return PlainTextResponse(report, media_type="text/markdown")

@app.get("/scan/{scan_id}/report/executive")
async def get_executive_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    s = scans[scan_id]
    return PlainTextResponse(generate_executive_report(
        s.get("target", ""), s.get("recon", {}), s.get("triaged_findings", []),
        s.get("analysis", {}), scope_policy.to_dict()
    ), media_type="text/markdown")

@app.get("/scan/{scan_id}/report/technical")
async def get_technical_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    s = scans[scan_id]
    return PlainTextResponse(generate_technical_report(
        s.get("target", ""), s.get("recon", {}), s.get("triaged_findings", []),
        s.get("analysis", {}), scope_policy.to_dict(), review_queue.get_all(scan_id, limit=500)
    ), media_type="text/markdown")

@app.get("/scan/{scan_id}/report/json")
async def get_json_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    s = scans[scan_id]
    return JSONResponse(generate_json_report(
        s.get("target", ""), s.get("recon", {}), s.get("triaged_findings", []),
        s.get("analysis", {}), scope_policy.to_dict(), review_queue.get_all(scan_id, limit=500)
    ))

@app.get("/scan/{scan_id}/report/csv")
async def get_csv_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    s = scans[scan_id]
    csv_text = generate_csv_report(s.get("triaged_findings", []))
    return Response(csv_text, media_type="text/csv",
                    headers={"Content-Disposition":"attachment; filename=burpollama_{}_findings.csv".format(scan_id)})

@app.get("/scan/{scan_id}/report/sarif")
async def get_sarif_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    sarif = generate_sarif_report(
        scan.get("target", ""),
        scan.get("triaged_findings", []),
        tool_version=app.version,
    )
    return JSONResponse(
        sarif,
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": (
                "attachment; filename=burpollama_{}.sarif".format(scan_id)
            )
        },
    )

@app.get("/scan/{scan_id}/report/download")
async def download_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    report = scans[scan_id].get("report","")
    target = scans[scan_id].get("target","target").replace("https://","").replace("http://","").split("/")[0]
    return PlainTextResponse(report, media_type="text/markdown",
        headers={"Content-Disposition":"attachment; filename=burpollama_{}.md".format(target)})

def _coverage_v2_for_scan(scan_id: str) -> dict:
    scan = scans[scan_id]
    analysis = scan.get("analysis", {})
    if analysis.get("coverage_v2"):
        return analysis.get("coverage_v2", {})
    return compute_coverage_v2(
        scan_id,
        scan.get("recon", {}),
        scan.get("triaged_findings", []),
        [f.get("affected_url") or f.get("url", "") for f in scan.get("triaged_findings", [])],
        scan.get("logs", []),
    )

def _bounty_for_scan(scan_id: str) -> dict:
    return build_bounty_mode(
        scans[scan_id],
        scope_policy.to_dict(),
        auth_matrix.stats,
        _coverage_v2_for_scan(scan_id),
    )

def _autopilot_state(scan: dict) -> str:
    status = str(scan.get("status", "queued")).lower()
    phase = str(scan.get("phase", "queued")).lower()
    if status == "paused":
        return "paused"
    if status == "stopped":
        return "stopped"
    if status in ("failed", "error"):
        return "failed"
    if status in ("complete", "completed"):
        return "completed"
    if status == "queued" or phase == "queued":
        return "queued"
    if "burp" in phase or "passive" in phase:
        return "waiting_for_burp_traffic"
    if any(x in phase for x in ("triage", "validat", "analysis", "proof", "hunt")):
        return "validating"
    if "report" in phase or "intelligence" in phase:
        return "reporting"
    return "running"

def _ready_to_submit_findings(bounty: dict) -> list[dict]:
    ready = []
    for f in bounty.get("ready_findings", bounty.get("confirmed_bounty_findings", [])):
        if (
            int(f.get("quality_score", 0) or 0) >= 85
            and str(f.get("grade") or f.get("quality_grade", "")).upper() == "A"
            and
            f.get("evidence_strength") == "strong"
            and f.get("impact")
            and f.get("steps_to_reproduce")
            and f.get("affected_asset")
            and f.get("remediation")
            and f.get("why_bounty_worthy")
        ):
            ready.append(f)
    return ready

def _autopilot_timeline(scan: dict) -> list[dict]:
    phase = str(scan.get("phase", "queued")).lower()
    state = _autopilot_state(scan)
    steps = [
        ("queued", "Queued"),
        ("recon", "Recon and URL discovery"),
        ("waf", "WAF and throttle calibration"),
        ("hunt", "Active/passive validation"),
        ("triage", "AI and proof triage"),
        ("analysis", "Deep analysis and attack graph"),
        ("reporting", "Report generation"),
        ("intelligence", "Analyst intelligence briefing"),
        ("completed", "Completed"),
    ]
    timeline = []
    active_seen = False
    for key, label in steps:
        if state == "completed":
            item_state = "completed"
        elif (
            key in phase
            or (key == "queued" and state == "queued")
            or (
                key == "reporting"
                and state == "reporting"
                and "intelligence" not in phase
            )
        ):
            item_state = state
            active_seen = True
        elif not active_seen:
            item_state = "completed" if state not in ("queued", "failed", "stopped", "paused") else "queued"
        else:
            item_state = "queued"
        timeline.append({"key": key, "label": label, "state": item_state})
    return timeline

def _autopilot_for_scan(scan_id: str) -> dict:
    scan = scans[scan_id]
    coverage = _coverage_v2_for_scan(scan_id)
    bounty = _bounty_for_scan(scan_id)
    graph = scan.get("analysis", {}).get("attack_graph", {})
    logs = scan.get("logs", [])[-200:]
    durable_run = autopilot_state.get_run(scan_id) or {}
    high_value = bounty.get("high_value_endpoints", [])
    coverage_gaps = {
        "untested_endpoints": coverage.get("untested_endpoints", coverage.get("untested_templates", 0)),
        "skipped_due_to_scope": coverage.get("skipped_due_to_scope", []),
        "skipped_due_to_rate_limit": coverage.get("skipped_due_to_rate_limit", 0),
        "skipped_due_to_missing_auth": coverage.get("skipped_due_to_missing_auth", 0),
        "skipped_due_to_safety_mode": coverage.get("skipped_due_to_safety_mode", 0),
        "high_risk_untested_urls": coverage.get("high_risk_untested_urls", coverage.get("top_untested", [])),
    }
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": scan.get("id", ""),
            "target": scan.get("target", ""),
            "status": scan.get("status", ""),
            "phase": scan.get("phase", ""),
            "started": scan.get("started", ""),
            "scheduler_task_id": scan.get("scheduler_task_id", ""),
            "resume_token": scan.get("autopilot_resume_token") or durable_run.get("resume_token", ""),
        },
        "progress_state": _autopilot_state(scan),
        "allowed_progress_states": [
            "queued", "running", "waiting_for_burp_traffic", "validating",
            "reporting", "completed", "paused", "stopped", "failed",
        ],
        "scope_summary": scope_policy.to_dict(),
        "automation_mode": {
            "scan_mode": scope_policy.to_dict().get("scan_mode", "conservative"),
            "passive_only_mode": scope_policy.to_dict().get("passive_only_mode", False),
            "active_testing_enabled": scope_policy.to_dict().get("active_testing_enabled", True),
            "authenticated_testing_enabled": scope_policy.to_dict().get("authenticated_testing_enabled", False),
            "oob_testing_enabled": scope_policy.to_dict().get("oob_testing_enabled", False),
            "cloud_ai_enabled": scope_policy.to_dict().get("cloud_ai_enabled", False),
        },
        "smart_throttle": scan.get("throttle") or throttle.status(),
        "agent_timeline": _autopilot_timeline(scan),
        "live_logs": logs,
        "durable_state": {
            "run": durable_run,
            "tasks": autopilot_state.tasks(scan_id),
            "events": autopilot_state.recent_events(scan_id, limit=100),
            "agent_outputs": autopilot_state.agent_outputs(scan_id, limit=50),
            "store": autopilot_state.status(),
        },
        "high_value_endpoints": high_value,
        "confirmed_findings": bounty.get("confirmed_bounty_findings", []),
        "valid_bugs": bounty.get("valid_bugs", []),
        "needs_more_proof": bounty.get("needs_more_proof", []),
        "candidate_findings": bounty.get("candidate_bounty_findings", []),
        "informational_findings": bounty.get("informational_findings", []),
        "false_positives_removed": bounty.get("false_positives_removed", []),
        "skipped_websites": bounty.get("skipped_websites", []),
        "missing_proof": bounty.get("missing_proof", []),
        "coverage_gaps": coverage_gaps,
        "attack_chains": graph.get("attack_paths", []),
        "intelligence": scan.get("intelligence", {}),
        "planner": scan.get("planner", {}),
        "planner_summary": scan.get("planner_summary", ""),
        "ready_to_submit": _ready_to_submit_findings(bounty),
    }

@app.get("/scan/{scan_id}/bounty")
async def get_bounty_mode(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    return JSONResponse(_bounty_for_scan(scan_id))

@app.get("/scan/{scan_id}/bounty/json")
async def get_bounty_mode_json(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    data = _bounty_for_scan(scan_id)
    export = {
        "generated_at": data.get("generated_at"),
        "selected_scan": data.get("selected_scan", {}),
        "zero_false_positive_mode": True,
        "note": "Only READY findings are included in bounty reports.",
        "ready_findings": data.get("ready_findings", []),
        "ready_count": len(data.get("ready_findings", [])),
    }
    return JSONResponse(export,
        headers={"Content-Disposition":"attachment; filename=burpollama_{}_bounty.json".format(scan_id)})

@app.get("/scan/{scan_id}/bounty/markdown")
async def get_bounty_mode_markdown(scan_id: str, platform: str = "hackerone"):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    platform = platform if platform.lower() in ("hackerone", "bugcrowd") else "hackerone"
    report = build_bounty_report(_bounty_for_scan(scan_id), platform=platform)
    return PlainTextResponse(report, media_type="text/markdown",
        headers={"Content-Disposition":"attachment; filename=burpollama_{}_{}_bounty.md".format(scan_id, platform.lower())})

@app.get("/scan/{scan_id}/bounty/report")
async def get_bounty_report(scan_id: str, platform: str = "hackerone"):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    scope = scope_policy.to_dict()
    session_status = auth_matrix.stats
    coverage = compute_coverage_v2(
        scan_id,
        scan.get("recon", {}),
        [finding for finding in findings_store if finding.get("scan_id") == scan_id],
        scan.get("recon", {}).get("urls", []),
        scan.get("logs", []),
    )
    data = build_bounty_mode(scan, scope, session_status, coverage)
    selected_platform = platform if platform.lower() in ("hackerone", "bugcrowd") else "hackerone"
    return PlainTextResponse(
        build_bounty_report(data, selected_platform),
        media_type="text/plain",
    )

@app.get("/scan/{scan_id}/bounty/finding/{finding_id}/markdown")
async def get_single_bounty_finding_markdown(scan_id: str, finding_id: str, platform: str = "hackerone"):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    platform = platform if platform.lower() in ("hackerone", "bugcrowd") else "hackerone"
    report = build_single_bounty_report(_bounty_for_scan(scan_id), finding_id, platform=platform)
    if not report: raise HTTPException(404,"Bounty finding not found")
    return PlainTextResponse(report, media_type="text/markdown")

@app.get("/scan/{scan_id}/autopilot")
async def get_autopilot_mode(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    return JSONResponse(_autopilot_for_scan(scan_id))

@app.get("/scan/{scan_id}/intelligence")
async def get_scan_intelligence(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(
        scans[scan_id].get("recon", {}).get("intelligence", {})
    )

@app.get("/scan/{scan_id}/planner")
async def get_scan_planner(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return JSONResponse({
        "scan_id": scan_id,
        "planner": scans[scan_id].get("planner", {}),
        "summary": scans[scan_id].get("planner_summary", ""),
    })

@app.get("/scan/{scan_id}/swarm")
async def get_scan_swarm(scan_id: str, minimum_pheromone: float = 0.0):
    if scan_id not in scans and not autopilot_state.get_run(scan_id):
        raise HTTPException(404, "Scan not found")
    status = swarm_blackboard.status(scan_id)
    status["hot_items"] = swarm_blackboard.query(
        scan_id,
        TriggerPredicate(
            minimum_pheromone=max(0.0, float(minimum_pheromone)),
            limit=100,
        ),
    )
    status["ready_agents"] = swarm_blackboard.ready_agents(scan_id)
    return JSONResponse(status)

@app.get("/scan/{scan_id}/playbook")
async def get_scan_playbook(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    existing = scan.get("playbook") or scan.get("analysis", {}).get("playbook")
    if existing:
        return JSONResponse(existing)
    findings = [
        finding for finding in findings_store
        if finding.get("scan_id") == scan_id
    ]
    playbook = build_scan_playbook(
        scan.get("recon", {}),
        findings,
        _coverage_v2_for_scan(scan_id),
        scan.get("planner", {}),
    )
    scan["playbook"] = playbook
    return JSONResponse(playbook)

@app.get("/scan/{scan_id}/auth-coverage")
async def get_scan_auth_coverage(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    existing = scan.get("auth_coverage") or scan.get("analysis", {}).get("auth_coverage")
    if existing:
        return JSONResponse(existing)
    findings = [
        finding for finding in findings_store
        if finding.get("scan_id") == scan_id
    ]
    report = analyze_auth_coverage(
        scan.get("recon", {}),
        auth_matrix.stats,
        findings,
        _coverage_v2_for_scan(scan_id),
    )
    scan["auth_coverage"] = report
    return JSONResponse(report)

@app.get("/intelligence/program")
async def get_program_intelligence(slug: str):
    policy = await fetch_hackerone_scope(slug)
    return {
        "slug": slug,
        "available": bool(policy),
        "program": policy,
        "attractiveness": score_program_attractiveness(policy),
    }

@app.get("/intelligence/program/playbook")
async def get_program_playbook(slug: str, tech: str = ""):
    policy = await fetch_hackerone_scope(slug)
    tech_stack = [item.strip() for item in tech.split(",") if item.strip()]
    return {
        "slug": slug,
        "available": bool(policy),
        "playbook": build_program_playbook(policy, tech_stack),
    }

@app.get("/intelligence/cve")
async def get_cve_intelligence(tech: str):
    return {
        "technology": tech,
        "cves": await lookup_nvd_cve(tech),
    }

@app.get("/scan/{scan_id}/autopilot/report")
async def get_autopilot_report(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    data = _autopilot_for_scan(scan_id)
    lines = [
        "# BurpOllama Autopilot Report",
        "",
        "- **Scan:** `{}`".format(data["scan"]["id"]),
        "- **Target:** `{}`".format(data["scan"]["target"]),
        "- **State:** `{}`".format(data["progress_state"]),
        "- **Confirmed findings:** {}".format(len(data["confirmed_findings"])),
        "- **Candidate findings:** {}".format(len(data["candidate_findings"])),
        "- **Ready to submit:** {}".format(len(data["ready_to_submit"])),
        "",
        "## Ready To Submit",
        "",
    ]
    for f in data["ready_to_submit"]:
        lines.extend([
            "### {}".format(f.get("title", "")),
            "",
            "- **Affected asset:** `{}`".format(f.get("affected_asset", "")),
            "- **Severity:** {}".format(f.get("severity", "")),
            "- **Confidence:** {}%".format(f.get("confidence", "")),
            "- **Impact:** {}".format(f.get("impact", "")),
            "- **Why bounty-worthy:** {}".format(f.get("why_bounty_worthy", "")),
            "",
        ])
    return PlainTextResponse("\n".join(lines), media_type="text/markdown",
        headers={"Content-Disposition":"attachment; filename=burpollama_{}_autopilot.md".format(scan_id)})

@app.get("/scans")
async def list_scans():
    return [{"id":s["id"],"target":s["target"],"status":s["status"],
             "phase":s["phase"],"started":s["started"]} for s in scans.values()]

@app.post("/analyze")
async def analyze_burp_traffic(payload: BurpTraffic):
    ok, reason = scope_policy.validate_target(payload.request_url, action="passive")
    if not ok:
        return {"queued": False, "blocked_by_scope": True, "reason": reason}
    stats["burp_requests"] += 1
    fp = fingerprint_http(
        payload.request_method,
        payload.request_url,
        payload.request_body or "",
        payload.response_status or 0,
        payload.response_headers or "",
        payload.response_body or "",
    )
    is_new_response, cluster_id = response_deduper.add(fp)
    metrics.inc("burp.requests")
    if not is_new_response:
        stats["deduped_responses"] += 1
    api_key = _gc.GEMINI_API_KEY

    # ── Instant pattern scan (always runs) ───────────────────────────────────
    hits = await pattern_scan_traffic(payload)
    for f in hits:
        findings_store.append(f)
        stats[f["severity"]] += 1
        stats["total"]        += 1
        await broadcast({"type":"finding","data":f})

    # ── Heuristic pre-filter — gate before Gemini queue ──────────────────────
    # Extracts content-type from headers for the filter decision
    req_ct  = ""
    resp_ct = ""
    for line in (payload.request_headers or "").splitlines():
        if line.lower().startswith("content-type:"):
            req_ct = line.split(":",1)[1].strip()
            break
    for line in (payload.response_headers or "").splitlines():
        if line.lower().startswith("content-type:"):
            resp_ct = line.split(":",1)[1].strip()
            break

    queue_it, reason = pre_filter.should_queue(
        method          = payload.request_method,
        url             = payload.request_url,
        request_ct      = req_ct,
        response_ct     = resp_ct,
        request_body    = payload.request_body or "",
        response_status = payload.response_status or 200,
    )

    if api_key and queue_it and is_new_response:
        await burp_queue.put((payload, api_key))

    await broadcast({"type":"stats","data":dict(stats)})

    # Passive delta highlighting — check if this URL is new surface area
    await delta_tracker.check_and_alert(payload.request_url)

    return {
        "queued":           queue_it,
        "queue_reason":     reason,
        "instant_findings": len(hits),
        "filter_stats":     pre_filter.stats,
        "delta_count":      delta_tracker.delta_count,
        "fingerprint":      fp.as_dict(),
        "cluster_id":       cluster_id,
        "deduped":          not is_new_response,
    }

@app.get("/findings")
async def get_findings(severity: Optional[str]=None, verdict: Optional[str]=None,
                       source: Optional[str]=None, limit: int=500):
    data = evaluate_findings(findings_store)
    for finding in data:
        scan = scans.get(finding.get("scan_id"), {})
        chain_data = (
            scan.get("exploit_chains")
            or scan.get("analysis", {}).get("exploit_chains")
        )
        finding.update(score_impact_finding(finding, chain_data))
    if severity: data=[f for f in data if f.get("severity","").upper()==severity.upper()]
    if verdict:  data=[f for f in data if f.get("verdict","")==verdict]
    if source:   data=[f for f in data if f.get("source","")==source]
    return {"findings":data[-limit:],"total":len(findings_store)}

@app.get("/findings/{scan_id}/buckets")
async def get_finding_buckets(scan_id: str):
    findings = [f for f in findings_store if f.get("scan_id") == scan_id]
    scan = scans.get(scan_id, {})
    chain_data = (
        scan.get("exploit_chains")
        or scan.get("analysis", {}).get("exploit_chains")
        or build_exploit_chains(findings)
    )
    gated = apply_zero_fp_gate(
        findings,
        scope_policy.to_dict(),
        chain_data,
        tech_stack=scan.get("recon", {}).get("tech_stack", []),
        scan_context={"recon": scan.get("recon", {})},
    )
    eliminated = sum(
        1
        for finding in gated.get("false_positives_removed", [])
        if any(
            str(check).startswith("fp_eliminator:")
            for check in finding.get("zero_fp_failed_checks", [])
        )
    )
    await log_broadcast(
        scan_id,
        "FP eliminator removed {} finding(s) before the 12-point gate".format(
            eliminated
        ),
        "info",
    )
    return {
        "scan_id": scan_id,
        "summary": {name: len(items) for name, items in gated.items()},
        **gated,
    }

@app.get("/findings/export")
async def export_findings():
    return JSONResponse(
        {"findings":findings_store,"stats":dict(stats),
         "exported_at":datetime.utcnow().isoformat()},
        headers={"Content-Disposition":"attachment; filename=burpollama_findings.json"})

@app.get("/findings/export/csv")
async def export_findings_csv():
    return Response(generate_csv_report(findings_store), media_type="text/csv",
                    headers={"Content-Disposition":"attachment; filename=burpollama_findings.csv"})

@app.get("/findings/{finding_id}/submission")
async def get_submission(finding_id: str, platform: str = "hackerone"):
    f = next((x for x in findings_store if x["id"]==finding_id), None)
    if not f: raise HTTPException(404,"Finding not found")
    if platform.lower() == "bugcrowd":
        report = generate_bugcrowd_report(f)
    elif platform.lower() == "hackerone":
        report = generate_h1_report(f)
    else:
        report = generate_submission(f)
    return PlainTextResponse(report, media_type="text/markdown")

@app.delete("/findings")
async def clear_findings():
    findings_store.clear(); stats.clear()
    await broadcast({"type":"clear"})
    return {"cleared":True}

@app.get("/stats")
async def get_stats():
    severity_counts = defaultdict(int)
    for finding in findings_store:
        severity_counts[str(finding.get("severity", "INFO")).upper()] += 1
    return {
        **dict(stats),
        "total": len(findings_store),
        "CRITICAL": severity_counts["CRITICAL"],
        "HIGH": severity_counts["HIGH"],
        "active_scans": sum(
            1 for scan in scans.values()
            if str(scan.get("status", "")).lower() in ("queued", "running", "paused")
        ),
    }

@app.get("/health")
async def health(target: Optional[str] = None):
    key = _gc.GEMINI_API_KEY
    ok  = False
    target_reachable = None
    checked_target = None
    if key:
        try:
            if ai_privacy_guard.is_cloud_allowed():
                async with httpx.AsyncClient(timeout=5) as c:
                    r  = await c.get(
                        "https://generativelanguage.googleapis.com/v1beta/models?key={}".format(key))
                    ok = r.status_code == 200
        except Exception: pass
    if target:
        checked_target = target.strip()
        if checked_target and not re.match(r"^https?://", checked_target, re.I):
            checked_target = "https://" + checked_target
        try:
            parsed = httpx.URL(checked_target)
            if parsed.scheme not in ("http", "https") or not parsed.host:
                raise ValueError("Invalid target URL")
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                response = await client.get(checked_target)
            target_reachable = response.status_code < 500
        except Exception:
            target_reachable = False
    return {
        "status":"ok","gemini_api":"connected" if ok else "disconnected",
        "api_key_set":bool(key),
        "target": checked_target,
        "target_reachable": target_reachable,
        "burp_queue":burp_queue.qsize(),
        "findings_stored":len(findings_store),
        "active_scans":sum(1 for s in scans.values() if s["status"]=="running"),
        "throttle_mult":throttle._backoff_mult,
        "throttle_blocks":throttle._total_blocks,
        "throttle": throttle.status(),
        "fingerprinting": response_deduper.stats(),
        "scheduler": scheduler.status(),
        "oob_available": oob.available,
        "oob_domain": oob.domain,
        "oob_payloads": oob.payload_count,
        "scope": scope_policy.to_dict(),
    }


@app.get("/test-connection")
async def test_connection(url: str):
    checked_url = str(url or "").strip()
    if checked_url and not re.match(r"^https?://", checked_url, re.I):
        checked_url = "http://" + checked_url
    try:
        parsed = httpx.URL(checked_url)
        if parsed.scheme not in ("http", "https") or not parsed.host:
            raise ValueError("Invalid target URL")
    except Exception as exc:
        return {
            "reachable": False,
            "status_code": None,
            "error": str(exc),
            "method_used": "httpx",
        }

    response, _method_url, error = await probe_target_connection(checked_url)
    if response is None:
        return {
            "reachable": False,
            "status_code": None,
            "error": error or "All connection attempts failed",
            "method_used": "httpx",
        }
    return {
        "reachable": response.status_code < 500,
        "status_code": response.status_code,
        "error": None,
        "method_used": "httpx",
    }


def _database_is_ready() -> bool:
    try:
        event_store.status()
        return True
    except Exception:
        return False


@app.get("/ready")
async def ready():
    availability = await ai_router.availability()
    return {
        "ready": True,
        "version": "3.0",
        "ai_configured": availability["triage_capable"],
        "ai_provider": availability["active_provider"],
        "ai_model": availability["active_model"],
        "scan_capable": True,
        "triage_capable": availability["triage_capable"],
        "database_ok": _database_is_ready(),
        "startup_time": STARTUP_TIME,
    }


@app.get("/ecosystem/agents")
async def ecosystem_agents():
    return {"agents": list_agents(), "count": len(list_agents())}


@app.get("/ecosystem/tools")
async def ecosystem_tools():
    tools = tool_status()
    return {
        "tools": tools,
        "available": sum(1 for tool in tools if tool["available"]),
        "total": len(tools),
    }


@app.get("/ecosystem/memory")
async def ecosystem_memory(limit: int = 20):
    memory = TechniqueMemory()
    return {
        "stats": memory.stats(),
        "recent": memory.recent(max(1, min(limit, 100))),
    }


@app.get("/ecosystem/web3/audit")
async def ecosystem_web3_audit(path: str):
    candidate = Path(path).expanduser().resolve()
    project_root = Path(__file__).resolve().parent
    if project_root not in candidate.parents and candidate != project_root:
        raise HTTPException(403, "Web3 audit paths must be inside the BurpOllama workspace.")
    if not candidate.exists():
        raise HTTPException(404, "Solidity path not found.")
    return audit_solidity_path(candidate)

def _smart_throttle_recommendation(backoff_multiplier: float, host_dead: bool) -> str:
    if backoff_multiplier >= 16 or host_dead:
        return "STOP - target is blocking all requests"
    if backoff_multiplier >= 8:
        return "Switch to Safe Passive Scan"
    if backoff_multiplier >= 4:
        return "Switch to Bounty Scan"
    return "Continue"

@app.get("/throttle/status")
async def get_throttle_status():
    state = throttle.status()
    backoff_multiplier = float(state.get("current_throttle_multiplier", 1.0) or 1.0)
    host_dead = bool(state.get("host_dead", False))
    return {
        "requests_per_minute_limit": int(scope_policy.config.max_requests_per_minute),
        "consecutive_blocks": int(state.get("consecutive_blocks", 0) or 0),
        "backoff_multiplier": backoff_multiplier,
        "host_dead": host_dead,
        "total_blocks": int(state.get("total_blocks", 0) or 0),
        "jitter_enabled": True,
        "last_block_reason": str(state.get("last_block_reason", "") or ""),
        "recommendation": _smart_throttle_recommendation(backoff_multiplier, host_dead),
    }

def _route_exists(path: str, method: str = "GET") -> bool:
    method = method.upper()
    for route in app.routes:
        if getattr(route, "path", "") == path and method in getattr(route, "methods", set()):
            return True
    return False

def _status(name: str, state: str, detail: str, data: Optional[dict] = None) -> dict:
    return {"name": name, "status": state, "detail": detail, "data": data or {}}

def _check_status(status: str, detail: str = "", data: Optional[dict] = None) -> dict:
    out = {"status": status, "detail": detail}
    if data is not None:
        out["data"] = data
    return out

def _route_path_contains(fragment: str) -> bool:
    return any(fragment in getattr(route, "path", "") for route in app.routes)

def _system_check_results() -> dict:
    server_url = "http://127.0.0.1:8888"
    dashboard_url = server_url + "/ui"

    try:
        with review_queue._conn() as conn:
            conn.execute("SELECT 1").fetchone()
        database = _check_status("ok", "review_queue database connection succeeded.")
    except Exception as exc:
        database = _check_status("error", str(exc))

    scheduler_tables = _check_status(
        "ok" if os.path.exists(getattr(scheduler, "db_path", "")) else "missing",
        "distributed_scheduler database exists." if os.path.exists(getattr(scheduler, "db_path", "")) else "distributed_scheduler database is missing.",
        {"db_path": getattr(scheduler, "db_path", "")},
    )

    ai_provider_status = ai_router.status()
    storage_status = event_store.status()
    enhancement_modules = {
        "idor_proof_engine": callable(prove_idor),
        "secret_validator": callable(validate_secret),
        "xss_proof_engine": callable(prove_xss),
        "graphql_auth_tester": callable(test_graphql_auth),
        "jwt_attack_suite": callable(test_jwt),
        "oauth_tester": callable(test_oauth_flow),
        "business_logic_classifier": callable(classify_business_logic_candidates),
        "report_quality_scorer": callable(score_finding),
        "js_endpoint_extractor": callable(extract_js_endpoints),
        "behavioral_anomaly_detector": callable(detect_anomalies),
        "prototype_pollution_tester": callable(test_prototype_pollution),
        "request_smuggling_detector": callable(detect_smuggling),
        "api_version_tester": callable(test_api_versions),
        "websocket_tester": callable(test_websocket_security),
        "ato_chain_detector": callable(detect_ato_chains),
        "adaptive_scan_engine": callable(profile_target),
        "exploit_chain_engine": callable(build_exploit_chains),
        "impact_scoring_engine": callable(score_impact_finding),
        "poc_generator": callable(generate_safe_poc),
        "class_25_stored_xss": callable(hunt_stored_xss),
        "class_26_dom_xss": callable(hunt_dom_xss),
        "class_27_blind_xss": callable(hunt_blind_xss),
        "class_28_csrf": callable(hunt_csrf),
        "class_29_path_traversal_lfi": callable(hunt_path_traversal_lfi),
        "class_30_nosql_injection": callable(hunt_nosql_injection),
        "class_31_os_command_injection": callable(hunt_os_command_injection),
        "class_32_host_header_injection": callable(hunt_host_header_injection),
        "class_33_crlf_injection": callable(hunt_crlf_injection),
        "class_34_default_credentials": callable(hunt_default_credentials),
        "class_35_websocket_security": callable(test_websocket_security),
        "class_36_session_security": callable(hunt_session_security),
        "class_37_clickjacking": callable(hunt_clickjacking),
        "class_38_browser_storage": callable(hunt_browser_storage),
        "swarm_blackboard": callable(swarm_blackboard.write),
        "scope_drift_guard": callable(scope_drift),
        "sarif_export": callable(generate_sarif_report),
    }
    checks = {
        "backend": _check_status("ok", "FastAPI backend is running."),
        "database": database,
        "scheduler_tables": scheduler_tables,
        "scope_controls": _check_status("ok" if scope_policy.config is not None else "error", "Scope controls are loaded."),
        "ai_privacy": _check_status("ok" if ai_privacy_guard.config is not None else "error", "AI privacy guard is loaded."),
        "bounty_routes": _check_status("ok" if _route_path_contains("/scan") else "error", "Scan/Bounty routes are registered."),
        "coverage_route": _check_status("ok" if _route_path_contains("/coverage") else "error", "Coverage route is registered."),
        "reports_route": _check_status("ok" if _route_path_contains("/report") else "error", "Report route is registered."),
        "oob_engine": _check_status(
            "available" if oob.available else "unavailable",
            "OOB engine is available." if oob.available else "OOB engine is unavailable or disabled.",
            {"domain": oob.domain, "payload_count": oob.payload_count},
        ),
        "burp_analyze": _check_status("ok" if _route_exists("/analyze", "POST") else "error", "Burp /analyze endpoint is registered."),
        "ai_providers": _check_status("ok", "AI provider status loaded.", {"providers": ai_provider_status.get("providers", [])}),
        "storage": _check_status("ok", "Event store status loaded.", storage_status),
        "enhancement_modules": _check_status(
            "ok" if all(enhancement_modules.values()) else "error",
            "All enhancement modules are importable."
            if all(enhancement_modules.values())
            else "One or more enhancement modules failed to load.",
            {"modules": enhancement_modules},
        ),
    }
    for module_name, loaded in enhancement_modules.items():
        checks["module_{}".format(module_name)] = _check_status(
            "ok" if loaded else "error",
            "{} is importable.".format(module_name)
            if loaded else "{} failed to load.".format(module_name),
        )
    statuses = [check["status"] for check in checks.values()]
    if "error" in statuses:
        overall = "error"
    elif any(status in statuses for status in ("missing", "unavailable")):
        overall = "degraded"
    else:
        overall = "healthy"
    return {
        "overall": overall,
        "checks": checks,
        "dashboard_url": dashboard_url,
        "api_url": server_url,
    }


async def _ai_provider_check_results() -> dict:
    availability = await ai_router.availability()
    configured = public_settings().get("configured", {})
    return {
        "ollama": {
            "status": "available" if availability["available"]["ollama"] else "unavailable",
            "models": availability["ollama_models"],
        },
        "gemini": {
            "status": "configured" if configured.get("GEMINI_API_KEY") else "not_configured",
        },
        "openai": {
            "status": "configured" if configured.get("OPENAI_API_KEY") else "not_configured",
        },
        "anthropic": {
            "status": "configured" if configured.get("ANTHROPIC_API_KEY") else "not_configured",
        },
        "active_provider": availability["active_provider"],
    }


async def _complete_system_check_results() -> dict:
    result = _system_check_results()
    result["ai_providers"] = await _ai_provider_check_results()
    return result

def _create_autopilot_dry_run() -> dict:
    scan_id = "dryrun-" + uuid.uuid4().hex[:8]
    target = "https://example.com"
    now = datetime.utcnow().isoformat()
    mock_scope = {
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
        "allowed_url_patterns": [],
        "blocked_url_patterns": [],
        "passive_only_mode": False,
        "active_testing_enabled": True,
        "emergency_stop": False,
        "scan_mode": "conservative",
    }
    mock_findings = normalize_findings([
        {
            "id": "DRY-IDOR-1",
            "scan_id": scan_id,
            "title": "IDOR exposes another user's account profile",
            "vulnerability_class": "IDOR/BOLA",
            "affected_url": target + "/api/users/2",
            "method": "GET",
            "parameter": "user_id",
            "severity": "HIGH",
            "confidence": 96,
            "exploitability_status": "confirmed",
            "evidence_strength": "strong",
            "false_positive_risk": "low",
            "business_impact": "An authenticated user can read another user's private profile data.",
            "technical_impact": "Object-level authorization is missing on the user endpoint.",
            "reproduction_steps": [
                "Authenticate with mock Session A.",
                "Request /api/users/2.",
                "Observe the synthetic Session B profile in the mock evidence.",
            ],
            "remediation": "Enforce object-level authorization on every user object request.",
            "redaction_status": "redacted",
            "evidence": "Mock confirmed proof: Session A received synthetic Session B profile data.",
            "verdict": "PASS",
        },
        {
            "id": "DRY-KEY-1",
            "scan_id": scan_id,
            "title": "Exposed API key in public JavaScript",
            "vulnerability_class": "Exposed API Key",
            "affected_url": target + "/static/app.js",
            "method": "GET",
            "severity": "HIGH",
            "confidence": 94,
            "exploitability_status": "confirmed",
            "evidence_strength": "strong",
            "false_positive_risk": "low",
            "business_impact": "A validated credential could allow unauthorized API usage.",
            "technical_impact": "A secret was embedded in a publicly retrievable JavaScript asset.",
            "reproduction_steps": [
                "Request /static/app.js from the mock dataset.",
                "Locate the redacted API key marker.",
                "Confirm the fixture marks the key as valid without contacting a real service.",
            ],
            "remediation": "Revoke the exposed key and move secrets to server-side secret storage.",
            "redaction_status": "redacted",
            "evidence": "Mock validated key: sk_test_[REDACTED].",
            "verdict": "PASS",
        },
        {
            "id": "DRY-SSRF-1",
            "scan_id": scan_id,
            "title": "SSRF candidate without OOB proof",
            "vulnerability_class": "SSRF",
            "affected_url": target + "/api/fetch?url=https://callback.invalid",
            "method": "POST",
            "parameter": "url",
            "severity": "HIGH",
            "confidence": 68,
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "medium",
            "business_impact": "Potential access to internal services requires confirmation.",
            "technical_impact": "The endpoint accepts a user-controlled URL.",
            "reproduction_steps": ["Submit the harmless mock callback URL to the fixture."],
            "remediation": "Allowlist outbound destinations and block private address ranges.",
            "redaction_status": "redacted",
            "evidence": "Mock request accepted; no OOB callback exists.",
            "verdict": "DOWNGRADE",
        },
        {
            "id": "DRY-HEADER-1",
            "scan_id": scan_id,
            "title": "Missing Content-Security-Policy header",
            "vulnerability_class": "Missing Security Header",
            "affected_url": target + "/",
            "method": "GET",
            "severity": "INFO",
            "confidence": 90,
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "low",
            "business_impact": "",
            "technical_impact": "The mock response omits Content-Security-Policy.",
            "reproduction_steps": ["Inspect the mock response headers."],
            "remediation": "Deploy a restrictive Content-Security-Policy appropriate for the application.",
            "redaction_status": "redacted",
            "evidence": "Mock response headers contain no Content-Security-Policy field.",
            "verdict": "DOWNGRADE",
        },
    ], scan_id=scan_id)
    findings_store.extend(mock_findings)
    gated = apply_zero_fp_gate(mock_findings, mock_scope)
    coverage = {
        "discovered_endpoints": 12,
        "tested_endpoints": 8,
        "untested_endpoints": 4,
    }
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "complete",
        "phase": "complete",
        "control": "run",
        "started": now,
        "finished": now,
        "logs": [
            {"ts": "00:00:00", "level": "phase", "msg": "Dry run queued"},
            {"ts": "00:00:01", "level": "success", "msg": "Mock recon loaded"},
            {"ts": "00:00:02", "level": "success", "msg": "Mock bounty finding normalized"},
            {"ts": "00:00:03", "level": "success", "msg": "Dry run complete"},
        ],
        "recon": {
            "domain": "example.com",
            "live_hosts": [{"url": target, "status": 200, "tech": ["GraphQL", "Express.js"]}],
            "urls": [target + "/api/users/2", target + "/admin", target + "/graphql"],
            "content_discovery": [
                {"url": target + "/admin", "path": "/admin", "status": 403, "size": 128, "auth_required": True, "source": "dry-run"},
                {"url": target + "/api/v1", "path": "/api/v1", "status": 200, "size": 256, "auth_required": False, "source": "dry-run"},
            ],
            "stats": {"subdomains": 1, "live_hosts": 1, "urls_raw": 12, "urls_clustered": 12, "content_discovery": 2, "content_401_403": 1, "js_findings": 1},
        },
        "triaged_findings": mock_findings,
        "raw_findings": mock_findings,
        "analysis": {
            "coverage_v2": coverage,
            "attack_graph": build_attack_graph(mock_findings).to_dict(),
        },
        "report": "# BurpOllama Dry Run Report\n\nSynthetic local-only Autopilot dry run completed.",
    }
    token = autopilot_state.create_run(scan_id, target, status="completed", phase="completed")
    scans[scan_id]["autopilot_resume_token"] = token
    autopilot_state.update_run(scan_id, status="completed", phase="completed", checkpoint={"dry_run": True}, finished=True)
    autopilot_state.upsert_task(scan_id, "dry_run", "completed", {"mock": True})
    autopilot_state.output(scan_id, "dry-run", "mock_scan", {
        "finding_ids": [finding["id"] for finding in mock_findings],
        "target": target,
    })
    return {
        "ok": True,
        "scan_id": scan_id,
        "scan_mode": "Bounty Scan",
        "target": "https://example.com (dry run — no real requests made)",
        "scope": mock_scope,
        "coverage": coverage,
        "summary": {name: len(items) for name, items in gated.items()},
        "valid_bugs_count": len(gated["valid_bugs"]),
        "needs_more_proof_count": len(gated["needs_more_proof"]),
        "candidates_count": len(gated["candidates"]),
        "informational_count": len(gated["informational"]),
        **gated,
    }

@app.get("/system-check")
async def get_system_check():
    return JSONResponse(await _complete_system_check_results())

@app.get("/system/check")
async def get_system_check_compat():
    """Beginner settings compatibility route."""
    result = await _complete_system_check_results()
    result["ollama"] = await _ollama_model_status()
    result["config"] = {
        "env_exists": public_settings().get("env_exists", False),
        "configured": public_settings().get("configured", {}),
    }
    return JSONResponse(result)

@app.post("/system-check/run")
async def run_system_check():
    return JSONResponse(await _complete_system_check_results())

@app.get("/autopilot/dry-run")
@app.post("/autopilot/dry-run")
async def autopilot_dry_run():
    return JSONResponse(_create_autopilot_dry_run())

@app.get("/metrics")
async def get_metrics():
    return PlainTextResponse(metrics.prometheus(), media_type="text/plain")

@app.get("/observability")
async def get_observability():
    return metrics.health()

@app.get("/ai/providers")
async def get_ai_providers():
    status = ai_router.status()
    availability = await ai_router.availability()
    for provider in status.get("providers", []):
        key = "ollama" if provider.get("name") == "local" else provider.get("name")
        provider["available"] = bool(availability["available"].get(key, False))
        provider["active"] = availability["active_provider"] == key
    status["active_provider"] = availability["active_provider"]
    status["active_model"] = availability["active_model"]
    status["triage_capable"] = availability["triage_capable"]
    return status

@app.get("/ai/privacy")
async def get_ai_privacy():
    return ai_privacy_guard.to_dict()

@app.post("/ai/privacy")
async def set_ai_privacy(cfg: dict):
    return ai_privacy_guard.update(cfg)

@app.get("/ai/audit")
async def get_ai_audit(limit: int = 200):
    return {"events": ai_privacy_guard.audit_log(limit=limit)}

@app.get("/scope")
async def get_scope():
    return scope_policy.to_dict()

@app.post("/auto/profile-target")
async def auto_profile_target(payload: dict):
    target = str(payload.get("target", "")).strip()
    if not target:
        raise HTTPException(422, "Enter a website to profile.")
    if not bool(payload.get("authorization_confirmed", False)):
        raise HTTPException(
            403,
            "Confirm that you own the target or have written permission to test it.",
        )
    allowed, reason = scope_policy.validate_target(target, action="scan")
    if not allowed:
        raise HTTPException(403, reason)
    try:
        profile = await profile_target(target, scope_policy)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    plan = build_adaptive_plan(
        profile,
        str(payload.get("scan_mode", "") or ""),
    )
    if len(target_profile_cache) >= 100:
        oldest_target = min(
            target_profile_cache,
            key=lambda key: target_profile_cache[key][0],
        )
        target_profile_cache.pop(oldest_target, None)
    target_profile_cache[target] = (time.time(), profile.to_dict())
    return {
        "target_profile": profile.to_dict(),
        "adaptive_plan": plan.to_dict(),
        "warning": (
            "Make sure you have written authorization to test this target."
            if not scope_policy.config.allowed_domains
            else ""
        ),
        "summary": "Target Profile: {} | Recommended Scan: {} SCAN".format(
            profile.profile_type,
            plan.level,
        ),
    }

@app.post("/scope")
async def set_scope(cfg: dict):
    updated = scope_policy.update(cfg)
    if "cloud_ai_enabled" in cfg:
        ai_privacy_guard.update({"cloud_ai_enabled": bool(cfg.get("cloud_ai_enabled"))})
    event_store.audit("local-user", "scope.update", "scope", updated)
    await broadcast({"type": "scope_updated", "data": updated})
    return updated

@app.post("/scope/validate-target")
async def validate_scope_target(req: TargetValidationRequest):
    ok, reason = scope_policy.validate_target(req.target, action=req.action or "scan")
    return {
        "allowed": ok,
        "reason": reason,
        "warning": (
            "Make sure you have written authorization to test this target."
            if ok and not scope_policy.config.allowed_domains
            else ""
        ),
        "policy": scope_policy.to_dict(),
    }

@app.post("/scope/emergency-stop")
async def emergency_stop():
    policy = scope_policy.update({"emergency_stop": True})
    stopped_scan_ids = []
    cancelled_task_ids = []
    now = datetime.utcnow().isoformat()

    for scan_id, scan in scans.items():
        if str(scan.get("status", "")).lower() in ("complete", "completed", "stopped"):
            continue
        scan.update({
            "control": "stop",
            "status": "stopped",
            "phase": "stopped",
            "error": "Emergency stop activated.",
        })
        stopped_scan_ids.append(scan_id)
        autopilot_state.update_run(
            scan_id,
            status="stopped",
            phase="stopped",
            checkpoint={"emergency_stop": True, "stopped_at": now},
            finished=True,
        )
        autopilot_state.upsert_task(
            scan_id,
            "full_pipeline",
            "stopped",
            error="Emergency stop activated.",
        )
        await broadcast({
            "type": "scan_stopped",
            "scan_id": scan_id,
            "reason": "Emergency stop activated.",
        })

    try:
        with scheduler._conn() as conn:
            rows = conn.execute("""
                SELECT id, scan_id FROM scan_tasks
                WHERE status IN ('QUEUED', 'RUNNING')
            """).fetchall()
            cancelled_task_ids = [row["id"] for row in rows]
            conn.execute("""
                UPDATE scan_tasks
                SET status='CANCELLED', last_error=?, worker_id=NULL, updated_at=?
                WHERE status IN ('QUEUED', 'RUNNING')
            """, ("Emergency stop activated.", now))
        for row in rows:
            scheduler.emit_event(
                row["scan_id"],
                "task.cancelled",
                {"task_id": row["id"], "reason": "emergency_stop"},
            )
    except Exception as exc:
        event_store.append("system", "scope.emergency_stop.scheduler_error", {"error": str(exc)})

    event_store.audit(
        "local-user",
        "scope.emergency_stop",
        "scope",
        {
            "stopped_scan_ids": stopped_scan_ids,
            "cancelled_task_ids": cancelled_task_ids,
        },
    )
    await broadcast({
        "type": "emergency_stop",
        "enabled": True,
        "stopped_scan_ids": stopped_scan_ids,
        "cancelled_task_ids": cancelled_task_ids,
    })
    return {
        "ok": True,
        "emergency_stop": policy.get("emergency_stop", False),
        "stopped_scan_ids": stopped_scan_ids,
        "cancelled_task_ids": cancelled_task_ids,
    }

@app.get("/scheduler")
async def get_scheduler():
    return scheduler.status()

@app.get("/autopilot/state")
async def get_autopilot_state():
    return autopilot_state.status()

@app.get("/fresh-scope/status")
async def get_fresh_scope_status():
    return fresh_scope_hunter.status()

@app.get("/fresh-scope/candidates")
async def get_fresh_scope_candidates(limit: int = 100, status: str = ""):
    return {
        "candidates": fresh_scope_hunter.candidates(limit=limit, status=status),
    }

@app.post("/fresh-scope/config")
async def set_fresh_scope_config(cfg: dict):
    updated = fresh_scope_hunter.update_config(cfg)
    event_store.audit(
        "local-user",
        "fresh_scope.config",
        "fresh-scope-agent",
        updated.get("config", {}),
    )
    return updated

@app.post("/fresh-scope/authorize")
async def authorize_fresh_scope_program(req: FreshScopeAuthorizationRequest):
    if not req.authorization_confirmed:
        raise HTTPException(
            403,
            "Confirm that you have written authorization for these exact assets.",
        )
    try:
        authorization = fresh_scope_hunter.authorize(
            req.platform,
            req.program_id,
            req.asset_patterns,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    event_store.audit(
        "local-user",
        "fresh_scope.authorize",
        "{}:{}".format(req.platform, req.program_id),
        {"asset_patterns": req.asset_patterns},
    )
    return authorization

@app.delete("/fresh-scope/authorize")
async def revoke_fresh_scope_program(platform: str, program_id: str):
    revoked = fresh_scope_hunter.revoke(platform, program_id)
    event_store.audit(
        "local-user",
        "fresh_scope.revoke",
        "{}:{}".format(platform, program_id),
        {"revoked": revoked},
    )
    return {"revoked": revoked}

@app.post("/fresh-scope/check")
async def check_fresh_scope_now():
    result = await fresh_scope_hunter.check_now(_launch_fresh_scope_scan)
    event_store.audit(
        "local-user",
        "fresh_scope.check",
        "fresh-scope-agent",
        result,
    )
    return result

@app.get("/storage")
async def get_storage():
    return event_store.status()

@app.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scans[scan_id]["control"] = "pause"
    scans[scan_id]["status"] = "paused"
    autopilot_state.update_run(scan_id, status="paused", phase=scans[scan_id].get("phase", "paused"))
    autopilot_state.upsert_task(scan_id, "full_pipeline", "paused")
    await broadcast({"type": "scan_paused", "scan_id": scan_id})
    return {"paused": True, "scan_id": scan_id}

@app.post("/scan/{scan_id}/resume")
async def resume_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scans[scan_id]["control"] = "run"
    scans[scan_id]["status"] = "running"
    autopilot_state.update_run(scan_id, status="running", phase=scans[scan_id].get("phase", "queued"))
    autopilot_state.upsert_task(scan_id, "full_pipeline", "running")
    await broadcast({"type": "scan_resumed", "scan_id": scan_id})
    return {"resumed": True, "scan_id": scan_id}


@app.post("/scan/{scan_id}/resume-from-checkpoint")
async def resume_scan_from_checkpoint(scan_id: str):
    completed_phases, restored_scan = _checkpoint_state(scan_id)
    events = event_store.stream(scan_id, limit=1000)
    if not events:
        raise HTTPException(404, "No checkpoint events found for scan")

    if scan_id in scans and scans[scan_id].get("_checkpoint_resume_running"):
        raise HTTPException(409, "Checkpoint resume is already running")
    if (
        scan_id in scans
        and scans[scan_id].get("status") == "running"
        and scans[scan_id].get("phase") not in {"error", "stopped", "complete"}
    ):
        raise HTTPException(409, "Scan is already running in memory")

    target = str(
        restored_scan.get("target")
        or scans.get(scan_id, {}).get("target")
        or ""
    )
    if not target:
        for event in events:
            payload = _decode_event_payload(event)
            if payload.get("target"):
                target = str(payload["target"])
                break
    if not target:
        raise HTTPException(409, "Checkpoint does not contain a target")

    if restored_scan:
        restored_scan["id"] = scan_id
        restored_scan["target"] = target
        restored_scan["control"] = "run"
        restored_scan["status"] = (
            "complete" if "intelligence" in completed_phases else "queued"
        )
        restored_scan.setdefault("logs", [])
        scans[scan_id] = restored_scan
    else:
        scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "queued",
            "phase": "queued",
            "control": "run",
            "started": datetime.utcnow().isoformat(),
            "logs": [],
        }
    _restore_checkpoint_findings(scan_id, scans[scan_id])

    remaining = [
        phase for phase in CHECKPOINT_PHASES
        if phase not in completed_phases
    ]
    if not remaining:
        scans[scan_id]["status"] = "complete"
        scans[scan_id]["phase"] = "complete"
        return {
            "resumed": False,
            "scan_id": scan_id,
            "completed_phases": sorted(completed_phases),
            "next_phase": None,
            "status": "already_complete",
        }

    scans[scan_id]["_checkpoint_resume_running"] = True
    scans[scan_id]["status"] = "running"
    scans[scan_id]["phase"] = remaining[0]
    event_store.append(
        scan_id,
        "scan.checkpoint_resume_requested",
        {
            "completed_phases": sorted(completed_phases),
            "next_phase": remaining[0],
        },
    )
    asyncio.create_task(_resume_pipeline_from_checkpoint(
        scan_id,
        target,
        _gc.GEMINI_API_KEY,
        set(completed_phases),
    ))
    await broadcast({
        "type": "scan_resumed",
        "scan_id": scan_id,
        "mode": "checkpoint",
        "next_phase": remaining[0],
    })
    return {
        "resumed": True,
        "scan_id": scan_id,
        "completed_phases": sorted(completed_phases),
        "next_phase": remaining[0],
        "status": "running",
    }


@app.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    if scans[scan_id].get("status") in ("complete", "completed"):
        return {"stopped": False, "scan_id": scan_id, "reason": "Scan already completed."}
    scans[scan_id]["control"] = "stop"
    scans[scan_id]["status"] = "stopped"
    scans[scan_id]["phase"] = "stopped"
    autopilot_state.update_run(scan_id, status="stopped", phase="stopped", finished=True)
    autopilot_state.upsert_task(scan_id, "full_pipeline", "stopped")
    await broadcast({"type": "scan_stopped", "scan_id": scan_id})
    return {"stopped": True, "scan_id": scan_id}

@app.post("/scan/{scan_id}/retry-failed-task")
async def retry_failed_task(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    if scan.get("status") not in ("failed", "error", "stopped"):
        return {"retried": False, "scan_id": scan_id, "reason": "No failed or stopped task to retry."}
    key = _gc.GEMINI_API_KEY
    scan["status"] = "queued"
    scan["phase"] = "queued"
    scan["control"] = "run"
    scan["error"] = ""
    task_id = scheduler.enqueue(scan_id, "full_pipeline_retry", {"target": scan.get("target", "")}, priority=5)
    scan["scheduler_task_id"] = task_id
    autopilot_state.update_run(scan_id, status="queued", phase="queued",
                               checkpoint={"retry_task_id": task_id})
    autopilot_state.upsert_task(scan_id, "full_pipeline_retry", "queued", {"scheduler_task_id": task_id})
    await log_broadcast(scan_id, "Retrying failed Autopilot task.", "info")
    asyncio.create_task(run_pipeline(scan_id, scan.get("target", ""), key))
    await broadcast({"type": "scan_resumed", "scan_id": scan_id})
    return {"retried": True, "scan_id": scan_id, "task_id": task_id}

@app.get("/scan/{scan_id}/coverage")
async def get_scan_coverage(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    recon_data = scan.get("recon", {})
    findings = [finding for finding in findings_store if finding.get("scan_id") == scan_id]
    prioritized_urls = recon_data.get("urls", [])
    return compute_coverage_v2(
        scan_id,
        recon_data,
        findings,
        prioritized_urls,
        scan.get("logs", []),
    )

@app.get("/scan/{scan_id}/coverage/v2")
async def get_scan_coverage_v2(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return _coverage_v2_for_scan(scan_id)

@app.get("/scan/{scan_id}/attack-graph")
async def get_scan_attack_graph(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    findings = [
        finding for finding in findings_store
        if finding.get("scan_id") == scan_id
        and str(finding.get("verdict", "")).upper() in ("PASS", "DOWNGRADE")
    ]
    graph = build_attack_graph(
        findings,
        scans[scan_id].get("ato_chains", []),
    ).to_dict()
    exploit_chains = (
        scans[scan_id].get("exploit_chains")
        or scans[scan_id].get("analysis", {}).get("exploit_chains")
        or build_exploit_chains(findings)
    )
    generated_exploit_chains = (
        scans[scan_id].get("generated_exploit_chains")
        or scans[scan_id].get("analysis", {}).get("generated_exploit_chains")
        or analyze_exploit_chains(findings)
    )
    scans[scan_id]["exploit_chains"] = exploit_chains
    scans[scan_id]["generated_exploit_chains"] = generated_exploit_chains
    graph["exploit_chains"] = exploit_chains
    graph["generated_exploit_chains"] = generated_exploit_chains
    return graph


@app.get("/scan/{scan_id}/ato-chains")
async def get_scan_ato_chains(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    chains = scans[scan_id].get("ato_chains")
    if chains is None:
        findings = [
            finding for finding in findings_store
            if finding.get("scan_id") == scan_id
        ]
        chains = detect_ato_chains(findings, scans[scan_id].get("recon", {}))
        scans[scan_id]["ato_chains"] = chains
    return {
        "scan_id": scan_id,
        "count": len(chains),
        "ato_chains": chains,
    }

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept(); ws_clients.add(ws)
    try:
        await ws.send_json({"type":"init","findings":findings_store[-100:],
                            "stats":dict(stats),
                            "scans":[{"id":s["id"],"target":s["target"],
                                      "status":s["status"],"phase":s["phase"]}
                                     for s in scans.values()]})
        while True: await ws.receive_text()
    except WebSocketDisconnect: pass
    finally: ws_clients.discard(ws)


@app.get("/review")
async def get_review_queue(scan_id: Optional[str] = None):
    """Return all AMBIGUOUS_PARSE findings pending manual review."""
    return {
        "pending": review_queue.get_pending(scan_id),
        "all":     review_queue.get_all(scan_id, limit=100),
        "count":   review_queue.count_pending(),
    }

@app.post("/review/{finding_id}/resolve")
async def resolve_review(finding_id: str, verdict: str = "PASS", note: str = ""):
    """Resolve an AMBIGUOUS_PARSE finding with a human verdict."""
    ok = review_queue.resolve(finding_id, verdict, note)
    return {"resolved": ok, "finding_id": finding_id, "verdict": verdict}

@app.post("/review/{finding_id}/note")
async def add_review_note(finding_id: str, body: ReviewNoteRequest):
    ok = review_queue.add_note(finding_id, body.note)
    return {"ok": ok, "finding_id": finding_id}

@app.post("/review/{finding_id}/escalate")
async def escalate_review(finding_id: str):
    """Re-inject an AMBIGUOUS_PARSE finding into the main pipeline as PASS."""
    f = review_queue.escalate(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    findings_store.append(f)
    stats[f["severity"]] += 1
    stats["total"]        += 1
    await broadcast({"type": "finding", "data": f})
    return {"escalated": True, "finding": f}

@app.get("/delta")
async def get_delta_stats():
    """Return passive delta tracking + WebSocket frame drop statistics."""
    return {
        **delta_tracker.stats,
        "ws_note": "ws_dropped_frames visible in Burp extension tab counter",
    }

_ui_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

def _render_ui() -> HTMLResponse:
    try:
        with open(_ui_file, "r", encoding="utf-8") as fh:
            return HTMLResponse(fh.read())
    except OSError:
        return HTMLResponse("<h1>BurpOllama UI not found</h1>", status_code=404)

@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse("/ui/start")

@app.get("/ui", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
async def ui_redirect():
    return RedirectResponse("/ui/start")

@app.get("/ui/{route:path}", include_in_schema=False)
async def ui_app(route: str = ""):
    return _render_ui()

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8888, reload=False, log_level="info")
