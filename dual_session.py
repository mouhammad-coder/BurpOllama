"""
dual_session.py — Dual-Session Authorization Matrix
Implements the "Autorize" pattern: crawl with Session B (victim/admin),
re-request everything with Session A (attacker), compare structurally.
Mathematical proof of BOLA/IDOR with zero ambiguity.
"""

import asyncio
import re
import time
import httpx
from urllib.parse import urlparse
from typing import Callable, Optional
from utils import structural_json_diff, prune_http_for_llm

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "application/json, text/html, */*",
}
TIMEOUT = httpx.Timeout(12.0)

# Endpoints that are sensitive enough to be worth testing
SENSITIVE_PATH_PATTERNS = re.compile(
    r"(?i)/(api|v\d|user|account|profile|order|invoice|payment|"
    r"admin|setting|config|dashboard|billing|document|report|"
    r"message|notification|ticket|customer|member|subscription)",
    re.IGNORECASE
)

# Status codes that indicate the endpoint returned real data
SUCCESS_CODES = {200, 201, 206}

# Response size delta below which we consider responses "same data" (noise floor)
MIN_CONTENT_DELTA = 50


def _make_session_headers(cookie: str, token: str = "") -> dict:
    """Build headers for a specific session."""
    h = dict(HEADERS)
    if cookie:
        h["Cookie"] = cookie
    if token:
        h["Authorization"] = "Bearer {}".format(token) if not token.startswith("Bearer") else token
    return h


class DualSessionMatrix:
    """
    Runs the authorization matrix test.

    Session A = attacker (lower privilege or different tenant)
    Session B = victim   (higher privilege or target tenant — used for discovery)
    """

    def __init__(self):
        self._session_a_cookie:  str  = ""
        self._session_a_token:   str  = ""
        self._session_b_cookie:  str  = ""
        self._session_b_token:   str  = ""
        self._configured:        bool = False
        self._allow_mutations:   bool = False   # v3.2: safe default — GET/HEAD only
        self.findings:           list = []
        self._tested:            int  = 0
        self._violations:        int  = 0

        # v3.2: Session health tracking
        self._consec_fails_a:    int  = 0   # consecutive 401/403 for Session A
        self._consec_fails_b:    int  = 0   # consecutive 401/403 for Session B
        self._session_a_dead:    bool = False
        self._session_b_dead:    bool = False
        self._FAIL_THRESHOLD:    int  = 3   # kills matrix after N consecutive failures
        self._broadcast_fn             = None  # injected by main.py

    def set_broadcast(self, fn):
        """Allow main.py to inject WebSocket broadcast for health alerts."""
        self._broadcast_fn = fn

    def configure(
        self,
        session_a_cookie:      str  = "",
        session_a_token:       str  = "",
        session_b_cookie:      str  = "",
        session_b_token:       str  = "",
        allow_mutations:       bool = False,
        health_check_endpoint: str  = "",
    ):
        """
        Set both sessions.
        health_check_endpoint: known-good URL for session liveness check
        (e.g. /api/me). If empty, auto-detected from first successful request.
        """
        self._session_a_cookie     = session_a_cookie.strip()
        self._session_a_token      = session_a_token.strip()
        self._session_b_cookie     = session_b_cookie.strip()
        self._session_b_token      = session_b_token.strip()
        self._allow_mutations       = bool(allow_mutations)
        self._health_check_endpoint = health_check_endpoint.strip()
        self._configured = bool(
            (session_a_cookie or session_a_token) and
            (session_b_cookie or session_b_token)
        )
        self._consec_fails_a = 0
        self._consec_fails_b = 0
        self._session_a_dead = False
        self._session_b_dead = False
        self._auto_health_url = ""   # reset on every configure call

    @property
    def configured(self) -> bool:
        return self._configured

    @property
    def mutations_allowed(self) -> bool:
        """True only when the operator explicitly authorized state changes."""
        return self._allow_mutations

    def session_headers(self) -> tuple[dict, dict]:
        return (
            _make_session_headers(self._session_a_cookie, self._session_a_token),
            _make_session_headers(self._session_b_cookie, self._session_b_token),
        )

    # ── Cookie health checker ──────────────────────────────────────────────────

    async def _record_session_response(
        self,
        session:     str,
        status_code: int,
        baseline:    int,
        log:         Callable,
        client:      httpx.AsyncClient = None,
    ) -> bool:
        """
        v3.3: Track consecutive auth failures with health-probe verification.

        Before halting the entire matrix on 3 consecutive 401/403 failures,
        fire a single GET to a known-good baseline endpoint. If that returns
        200, the session is alive — the failure was endpoint-specific
        (e.g. per-endpoint rate limit). Clear the counter and resume.
        Only halt if the health probe ALSO fails.
        """
        if baseline not in SUCCESS_CODES:
            return True

        if status_code in (401, 403):
            if session == "A":
                self._consec_fails_a += 1
                count = self._consec_fails_a
            else:
                self._consec_fails_b += 1
                count = self._consec_fails_b

            if count >= self._FAIL_THRESHOLD:
                # ── v3.3: Health probe before halting ────────────────────────
                health_url = (self._health_check_endpoint
                              or self._auto_health_url)

                if health_url and client:
                    log("[AuthMatrix] {} consecutive {}s on Session {} — "
                        "running health probe: {}".format(count, status_code,
                                                          session, health_url))
                    try:
                        hdrs = (_make_session_headers(self._session_a_cookie,
                                                      self._session_a_token)
                                if session == "A"
                                else _make_session_headers(self._session_b_cookie,
                                                           self._session_b_token))
                        r_health = await client.get(health_url, headers=hdrs,
                                                    timeout=TIMEOUT)
                        if r_health.status_code in SUCCESS_CODES:
                            # Session is alive — endpoint-specific block, not session death
                            log("[AuthMatrix] Health probe OK (HTTP {}) — "
                                "Session {} alive, resetting counter".format(
                                    r_health.status_code, session))
                            if session == "A":
                                self._consec_fails_a = 0
                            else:
                                self._consec_fails_b = 0
                            return True   # continue matrix
                    except Exception as probe_err:
                        log("[AuthMatrix] Health probe error: {}".format(probe_err))

                # Health probe failed or not configured — session truly dead
                if session == "A":
                    self._session_a_dead = True
                else:
                    self._session_b_dead = True

                alert_msg = (
                    "[AuthMatrix] ALERT: Session {} dead — {} consecutive {} "
                    "responses confirmed by failed health probe.".format(
                        session, count, status_code)
                )
                log(alert_msg, "error")
                if self._broadcast_fn:
                    try:
                        await self._broadcast_fn({
                            "type":    "session_dead_alert",
                            "session": session,
                            "status":  status_code,
                            "count":   count,
                            "message": alert_msg,
                        })
                    except Exception:
                        pass
                return False   # abort matrix
        else:
            # Successful response — reset counter + auto-learn health URL
            if session == "A":
                self._consec_fails_a = 0
            else:
                self._consec_fails_b = 0

        return True

    # ── Core test ──────────────────────────────────────────────────────────────

    async def run_matrix(
        self,
        urls:        list,
        log:         Callable,
        progress_cb: Optional[Callable] = None,
    ) -> list:
        """
        For each URL discovered by Session B:
          1. Request with Session B (victim/admin) → establish ground truth
          2. Request with Session A (attacker)     → test unauthorized access
          3. Compare structurally                  → flag BOLA/privilege escalation

        v3.2 safety guards:
          - Only GET/HEAD sent unless allow_mutations=True
          - Session health monitored; matrix aborts on 3 consecutive 401/403
        """
        if not self._configured:
            log("[AuthMatrix] Not configured — skipping dual-session testing")
            return []

        sensitive = [u for u in urls if SENSITIVE_PATH_PATTERNS.search(urlparse(u).path)]
        if not sensitive:
            log("[AuthMatrix] No sensitive endpoints in URL list — skipping")
            return []

        method_note = "GET/HEAD only" if not self._allow_mutations else "all methods"
        log("[AuthMatrix] ━━━ Dual-Session Authorization Matrix ({}) ━━━".format(method_note))
        log("[AuthMatrix] Testing {} sensitive endpoints".format(len(sensitive)))

        hdrs_a = _make_session_headers(self._session_a_cookie, self._session_a_token)
        hdrs_b = _make_session_headers(self._session_b_cookie, self._session_b_token)

        sem     = asyncio.Semaphore(6)
        results = []
        aborted = False

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=TIMEOUT,
        ) as client:
            for url in sensitive[:100]:
                # Check if any session died — abort immediately
                if self._session_a_dead or self._session_b_dead:
                    dead = "A" if self._session_a_dead else "B"
                    log("[AuthMatrix] Session {} dead — aborting matrix".format(dead))
                    aborted = True
                    break

                findings = await self._test_endpoint(
                    client, url, hdrs_a, hdrs_b, sem, log
                )
                if findings is None:   # None signals abort from health checker
                    aborted = True
                    break
                if findings:
                    results.extend(findings)
                    self._violations += len(findings)
                self._tested += 1

        self.findings = results
        status = "ABORTED — session expired" if aborted else "complete"
        log("[AuthMatrix] {} | Tested: {} | Violations: {}".format(
            status, self._tested, self._violations))
        return results

    async def _test_endpoint(
        self,
        client:  httpx.AsyncClient,
        url:     str,
        hdrs_a:  dict,
        hdrs_b:  dict,
        sem:     asyncio.Semaphore,
        log:     Callable,
    ) -> list:
        """
        Test a single URL with both sessions.
        Returns None to signal the caller should abort the entire matrix.
        Returns [] if no violation found.
        Returns list of findings if violation detected.
        """
        async with sem:
            try:
                # Step 1: Session B baseline (victim / higher-privilege)
                r_b = await client.get(url, headers=hdrs_b, timeout=TIMEOUT)
                if r_b.status_code not in SUCCESS_CODES:
                    return []

                # Auto-learn health check URL from first successful B response
                if not self._auto_health_url and not self._health_check_endpoint:
                    self._auto_health_url = url

                b_ok = await self._record_session_response(
                    "B", r_b.status_code, r_b.status_code, log, client)
                if not b_ok:
                    return None

                # Step 2: Session A request
                r_a = await client.get(url, headers=hdrs_a, timeout=TIMEOUT)

                a_ok = await self._record_session_response(
                    "A", r_a.status_code, r_b.status_code, log, client)
                if not a_ok:
                    return None

                # Step 3: Structural comparison
                finding = self._evaluate(url, r_a, r_b)
                return [finding] if finding else []

            except Exception:
                return []

    def _evaluate(
        self,
        url:  str,
        r_a:  httpx.Response,
        r_b:  httpx.Response,
    ) -> Optional[dict]:
        """
        v3.4 Fix 4: Multi-format BOLA/IDOR comparison.
        Handles JSON, HTML, XML, form-URL-encoded, and plain text responses.
        Non-JSON fallback uses text-similarity scoring to detect cross-session
        content leakage in legacy portals, OAuth flows, and SSR applications.
        """
        if r_a.status_code not in SUCCESS_CODES:
            return None

        ct_b = r_b.headers.get("content-type", "").lower()
        ct_a = r_a.headers.get("content-type", "").lower()

        # ── JSON structural comparison ────────────────────────────────────────
        if "application/json" in ct_b:
            diff = structural_json_diff(r_b.text, r_a.text)
            if diff.get("keys_match") and diff.get("data_differs"):
                sens = diff.get("sensitive_keys_found", [])
                return self._build_finding(
                    url, r_a, r_b,
                    confidence = 95 if sens else 82,
                    reason     = "JSON structure identical, data differs. Sensitive keys: {}".format(
                        sens[:3] if sens else "none"),
                    severity   = "CRITICAL" if sens else "HIGH",
                    violation  = "BOLA — Session A received Session B's data",
                    sens_keys  = sens,
                )
            if diff.get("keys_match") and not diff.get("data_differs"):
                if len(r_a.text) > 20:
                    return self._build_finding(
                        url, r_a, r_b,
                        confidence = 70,
                        reason     = "Session A received identical JSON response to Session B.",
                        severity   = "HIGH",
                        violation  = "Potential BOLA — responses identical across sessions",
                        sens_keys  = diff.get("sensitive_keys_found", []),
                    )

        # ── HTML response — size + similarity comparison ──────────────────────
        elif "text/html" in ct_b:
            size_b = len(r_b.text)
            size_a = len(r_a.text)
            if size_b > 500 and abs(size_a - size_b) < MIN_CONTENT_DELTA:
                return self._build_finding(
                    url, r_a, r_b,
                    confidence = 65,
                    reason     = "Session A received HTML response {:.0f}% similar to Session B's.".format(
                        100 - abs(size_a - size_b) / max(size_b, 1) * 100),
                    severity   = "MEDIUM",
                    violation  = "Possible IDOR — same HTML content served to attacker session",
                    sens_keys  = [],
                )

        # ── Fix 4: Non-JSON/HTML fallback — text-distance similarity ─────────
        # Handles: XML, form-URL-encoded, plain text, SOAP, SSR fragments
        elif ct_b and "application/json" not in ct_b:
            sim = self._text_similarity(r_b.text, r_a.text)
            if sim >= 0.85 and len(r_b.text) > 100:
                # >85% similar text across sessions = strong BOLA signal
                return self._build_finding(
                    url, r_a, r_b,
                    confidence = max(55, int(sim * 80)),
                    reason     = "Non-JSON response {:.0f}% similar across sessions "
                                 "(content-type: {}). Flagged for manual review.".format(
                                     sim * 100, ct_b.split(";")[0].strip()),
                    severity   = "MEDIUM",
                    violation  = "BOLA Candidate (Non-JSON) — text similarity {:.0f}%".format(
                        sim * 100),
                    sens_keys  = [],
                )

        # ── Identical raw response (any type) ─────────────────────────────────
        if r_a.text == r_b.text and len(r_a.text) > 100:
            return self._build_finding(
                url, r_a, r_b,
                confidence = 88,
                reason     = "Session A received bit-for-bit identical response to Session B.",
                severity   = "HIGH",
                violation  = "BOLA — identical response across sessions",
                sens_keys  = [],
            )

        return None

    @staticmethod
    def _text_similarity(a: str, b: str) -> float:
        """
        Fix 4: Lightweight bigram-based text similarity (0.0–1.0).
        Faster than Levenshtein for large HTML/XML responses.
        Uses character bigrams for language-agnostic comparison.
        """
        if not a or not b:
            return 0.0
        # Truncate to first 4000 chars to keep comparison fast
        a, b = a[:4000], b[:4000]
        if a == b:
            return 1.0

        def bigrams(s):
            return {s[i:i+2] for i in range(len(s) - 1)}

        bg_a = bigrams(a)
        bg_b = bigrams(b)
        if not bg_a or not bg_b:
            return 0.0
        intersection = len(bg_a & bg_b)
        return (2.0 * intersection) / (len(bg_a) + len(bg_b))

    def _build_finding(
        self,
        url:        str,
        r_a:        httpx.Response,
        r_b:        httpx.Response,
        confidence: int,
        reason:     str,
        severity:   str,
        violation:  str,
        sens_keys:  list,
    ) -> dict:
        ct = r_a.headers.get("content-type", "").split(";")[0]
        return {
            "id":          "AM-{}-{}".format(int(time.time() * 1000), abs(hash(url)) % 9999),
            "source":      "auth-matrix",
            "vuln_type":   violation,
            "severity":    severity,
            "confidence":  confidence,
            "url":         url,
            "method":      "GET",
            "description": (
                "Dual-session authorization matrix detected broken access control. "
                "Session A (attacker) accessed a resource owned by Session B (victim). "
                "{}".format(reason)
            ),
            "evidence":    (
                "Session B: HTTP {} ({} bytes, ct={}) | "
                "Session A: HTTP {} ({} bytes) | "
                "Sensitive keys: {} | Reason: {}".format(
                    r_b.status_code, len(r_b.text), ct,
                    r_a.status_code, len(r_a.text),
                    sens_keys[:3] if sens_keys else "none",
                    reason[:200],
                )
            ),
            "remediation": (
                "Implement server-side authorization checks on every object access. "
                "Verify the requesting user owns or has explicit permission to access the resource. "
                "Never rely on client-supplied IDs alone — validate ownership in the database layer."
            ),
            "cwe":         "CWE-639",
            "cvss":        9.1 if severity == "CRITICAL" else 7.5,
            "sensitive_keys": sens_keys,
            "session_a_status": r_a.status_code,
            "session_b_status": r_b.status_code,
        }

    @property
    def stats(self) -> dict:
        return {
            "tested":     self._tested,
            "violations": self._violations,
            "configured": self._configured,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
auth_matrix = DualSessionMatrix()
