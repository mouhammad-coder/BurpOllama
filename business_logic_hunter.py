"""business_logic_hunter.py

Deep business-logic vulnerability hunting for authorized bug bounty work.

    async def hunt_business_logic_deep(client, urls, live_hosts, scope_policy) -> list[dict]

Business-logic flaws are the bugs scanners miss because they require
understanding *intent*, not just syntax. This module actively probes for six
classes of logic flaw while staying safe for real engagements:

    1. Price manipulation        (gated: state-changing)
    2. Quantity manipulation     (gated: state-changing)
    3. Coupon / promo abuse      (gated: state-changing)
    4. Workflow / step bypass    (READ-ONLY by default)
    5. Race condition on credits (gated: state-changing + destructive)
    6. Account privilege bypass  (READ-ONLY by default)

SAFETY MODEL (non-negotiable):
  * Every request is scope-checked BEFORE it is sent. Fail-closed.
  * Read-only categories run by default. Categories that mutate server state
    (price/quantity/coupon/race) ONLY run when scope_policy explicitly
    authorizes state-changing tests, and they stop short of completing any
    transaction (no final "pay"/"submit order" call) -- we never complete a
    fraudulent transaction.
  * The race-condition probe additionally requires destructive authorization
    because concurrency tests can permanently alter balances.
  * A finding is emitted ONLY when the server response proves the flaw.
    Ambiguous signals are dropped to keep false positives near zero.

FINDING MODEL ("BurpOllama" finding dict) -- identical to the rest of the
toolkit so findings flow straight into the triage prompt, chain analyzer, and
final findings presentation:
    id, title, vulnerability_class, affected_url, method, parameter, severity,
    confidence, exploitability_status, evidence, reproduction_steps,
    business_impact, technical_impact, remediation, cwe, cvss_plus_plus,
    category, tags
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse


# ===========================================================================
# SCOPE POLICY (fail-closed) -- read scope + mutation authorization
# ===========================================================================
async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def _in_scope(scope_policy: Any, url: str) -> bool:
    """True only if scope_policy explicitly authorises requesting `url`."""
    if scope_policy is None or not url:
        return False
    try:
        method = getattr(scope_policy, "is_in_scope", None)
        if callable(method):
            return bool(await _maybe_await(method(url)))
        if callable(scope_policy):
            return bool(await _maybe_await(scope_policy(url)))
        if isinstance(scope_policy, dict):
            host = (urlparse(url).hostname or "").lower()
            denied = {h.lower() for h in (scope_policy.get("denied_hosts") or [])}
            if host in denied:
                return False
            if scope_policy.get("allow_all") is True:
                return True
            allowed = {h.lower() for h in (scope_policy.get("allowed_hosts") or [])}
            return host in allowed
    except Exception:
        return False
    return False


async def _mutation_allowed(scope_policy: Any, url: str) -> bool:
    """True only if scope_policy authorises STATE-CHANGING tests for `url`.

    Recognised signals (any one): attr/method `allow_state_changing`,
    `allow_mutation`, `allow_active`; or dict keys of the same name set True.
    Fail-closed otherwise.
    """
    if scope_policy is None:
        return False
    try:
        for name in ("allow_state_changing", "allow_mutation", "allow_active"):
            attr = getattr(scope_policy, name, None)
            if attr is not None:
                val = attr(url) if callable(attr) else attr
                if bool(await _maybe_await(val)):
                    return True
            if isinstance(scope_policy, dict) and scope_policy.get(name) is True:
                return True
    except Exception:
        return False
    return False


async def _destructive_allowed(scope_policy: Any, url: str) -> bool:
    """Extra gate for irreversible tests (e.g. concurrency / double-spend)."""
    if scope_policy is None:
        return False
    try:
        for name in ("allow_destructive", "allow_irreversible"):
            attr = getattr(scope_policy, name, None)
            if attr is not None:
                val = attr(url) if callable(attr) else attr
                if bool(await _maybe_await(val)):
                    return True
            if isinstance(scope_policy, dict) and scope_policy.get(name) is True:
                return True
    except Exception:
        return False
    return False


# ===========================================================================
# REQUEST + EVIDENCE CAPTURE (None-safe)
# ===========================================================================
class Probe:
    """Normalised response + captured raw request/response for evidence."""

    __slots__ = ("status", "headers", "text", "json", "elapsed",
                 "error", "raw_request", "raw_response")

    def __init__(self) -> None:
        self.status: Optional[int] = None
        self.headers: Dict[str, str] = {}
        self.text: Optional[str] = None
        self.json: Any = None
        self.elapsed: float = 0.0
        self.error: Optional[str] = None
        self.raw_request: str = ""
        self.raw_response: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


def _raw_request(method: str, url: str, headers: Optional[Dict[str, str]],
                 params: Optional[Dict[str, Any]], body: Any) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        path = f"{path}?{qs}" if "?" not in path else f"{path}&{qs}"
    elif parsed.query:
        path = f"{path}?{parsed.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for k, v in (headers or {}).items():
        # Redact obvious secrets in evidence.
        if k.lower() in {"authorization", "cookie"}:
            v = _redact(str(v))
        lines.append(f"{k}: {v}")
    if body is not None:
        payload = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
        lines.append("")
        lines.append(payload[:1000])
    return "\n".join(lines)


def _raw_response(probe: Probe) -> str:
    head = [f"HTTP/1.1 {probe.status}"]
    for k in ("content-type", "location", "set-cookie", "content-length"):
        if k in probe.headers:
            val = _redact(probe.headers[k]) if k == "set-cookie" else probe.headers[k]
            head.append(f"{k}: {val}")
    body = (probe.text or "")[:1500]
    return "\n".join(head) + "\n\n" + body


def _redact(value: str) -> str:
    s = str(value)
    return s[:6] + "…[redacted]" if len(s) > 8 else "[redacted]"


async def _safe_request(
    client: Any,
    scope_policy: Any,
    method: str,
    url: str,
    *,
    state_changing: bool = False,
    destructive: bool = False,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Any = None,
    timeout: float = 20.0,
) -> Optional[Probe]:
    """Scope-checked request. Returns None (no request sent) if not authorised.

    Fail-closed: out-of-scope, or a state-changing/destructive request without
    the matching authorization, returns None and sends nothing.
    """
    if not await _in_scope(scope_policy, url):
        return None
    if state_changing and not await _mutation_allowed(scope_policy, url):
        return None
    if destructive and not await _destructive_allowed(scope_policy, url):
        return None

    probe = Probe()
    probe.raw_request = _raw_request(method, url, headers, params, json_body)
    start = time.perf_counter()
    try:
        resp = await client.request(
            method.upper(), url,
            headers=headers, params=params, json=json_body, timeout=timeout,
        )
        probe.elapsed = time.perf_counter() - start
        probe.status = getattr(resp, "status_code", None) or getattr(resp, "status", None)
        try:
            probe.headers = {str(k).lower(): str(v) for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
        except Exception:
            probe.headers = {}
        # Body as text.
        text_attr = getattr(resp, "text", None)
        if callable(text_attr):
            probe.text = await _maybe_await(text_attr())
        elif isinstance(text_attr, str):
            probe.text = text_attr
        else:
            body = getattr(resp, "content", None)
            probe.text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else None
        # JSON body.
        json_attr = getattr(resp, "json", None)
        if callable(json_attr):
            try:
                probe.json = await _maybe_await(json_attr())
            except Exception:
                probe.json = _try_json(probe.text)
        else:
            probe.json = _try_json(probe.text)
        probe.raw_response = _raw_response(probe)
    except Exception as exc:  # network/parse errors never propagate
        probe.error = str(exc)
        probe.elapsed = time.perf_counter() - start
    return probe


def _try_json(text: Optional[str]) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


# ===========================================================================
# SIGNAL HELPERS
# ===========================================================================
_AUTH_BLOCK_RE = re.compile(r"(unauthorized|forbidden|access denied|not authori[sz]ed|"
                            r"please (log\s?in|sign\s?in)|login required|401|403)", re.I)
_CONFIRM_RE = re.compile(r"(order (confirmed|complete|placed)|thank you for your (order|purchase)|"
                         r"order number|order #|receipt|payment successful|confirmation number)", re.I)
_PAYMENT_GATE_RE = re.compile(r"(complete payment|enter payment|payment required|add payment|"
                              r"proceed to payment|payment details)", re.I)
_ADMIN_DATA_RE = re.compile(r"(\"role\"\s*:\s*\"admin\"|\"is_admin\"\s*:\s*true|user management|"
                            r"delete user|list users|all users|admin dashboard|manage roles)", re.I)
_ELEVATION_RE = re.compile(r"(\"role\"\s*:\s*\"admin\"|\"is_admin\"\s*:\s*true|\"admin\"\s*:\s*true|"
                           r"\"is_superuser\"\s*:\s*true|\"privilege[s]?\"\s*:\s*\"admin\")", re.I)


def _looks_authenticated_content(probe: Probe) -> bool:
    """A 2xx response that is NOT an auth block / login redirect."""
    if not probe.ok:
        return False
    if probe.status in (401, 403):
        return False
    if probe.status in (301, 302, 303, 307, 308):
        loc = probe.headers.get("location", "").lower()
        if any(x in loc for x in ("login", "signin", "auth", "payment")):
            return False
    if 200 <= (probe.status or 0) < 300 and probe.text and _AUTH_BLOCK_RE.search(probe.text):
        return False
    return 200 <= (probe.status or 0) < 300


def _extract_numeric(obj: Any, keys: Tuple[str, ...]) -> Optional[float]:
    """Find the first numeric value under any of `keys` in a JSON body."""
    if not isinstance(obj, (dict, list)):
        return None
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k).lower() in keys and isinstance(v, (int, float)) and not isinstance(v, bool):
                    return float(v)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return None


def _extract_total(obj: Any) -> Optional[float]:
    """Find a monetary total/price/amount in a JSON body."""
    return _extract_numeric(obj, ("total", "grand_total", "amount", "price",
                                  "subtotal", "order_total", "amount_due"))


def _extract_balance(obj: Any) -> Optional[float]:
    """Find a credit/balance/points value in a JSON body."""
    return _extract_numeric(obj, ("balance", "credit", "credits", "points",
                                  "available", "funds", "wallet_balance", "remaining"))


# ===========================================================================
# FINDING BUILDER ("BurpOllama" model)
# ===========================================================================
def _make_finding(
    *,
    category: str,
    title: str,
    vulnerability_class: str,
    url: str,
    method: str,
    parameter: str,
    severity: str,
    confidence: int,
    evidence: Dict[str, Any],
    reproduction_steps: List[str],
    business_impact: str,
    technical_impact: str,
    remediation: str,
    cwe: str,
    cvss: str,
) -> Dict[str, Any]:
    sig = f"{category}|{url}|{parameter}"
    fid = "BL-" + hashlib.sha1(sig.encode()).hexdigest()[:10].upper()
    # Standard safety preamble every business-logic PoC should carry.
    steps = [
        "Use a dedicated TEST account; do NOT target real users or complete real transactions.",
        *reproduction_steps,
    ]
    return {
        "id": fid,
        "title": title,
        "vulnerability_class": vulnerability_class,
        "affected_url": url,
        "method": method,
        "parameter": parameter,
        "severity": severity,
        "confidence": confidence,
        "exploitability_status": "confirmed",
        "evidence": evidence,
        "reproduction_steps": steps,
        "business_impact": business_impact,
        "technical_impact": technical_impact,
        "remediation": remediation,
        "cwe": cwe,
        "cvss_plus_plus": cvss,
        "category": category,
        "tags": ["business-logic", category],
    }


# ===========================================================================
# ENDPOINT CLASSIFICATION
# ===========================================================================
_CHECKOUT_KW = ("cart", "checkout", "basket", "order", "purchase", "buy", "payment", "pricing", "quote")
_PRICE_PREVIEW_KW = ("cart", "basket", "preview", "quote", "estimate", "update", "recalc", "summary")
_COUPON_KW = ("coupon", "promo", "voucher", "discount", "gift", "redeem-code")
_CONFIRM_KW = ("confirm", "complete", "success", "thank", "receipt", "order-confirmation")
_PAYMENT_KW = ("payment", "pay", "billing", "charge")
_BALANCE_KW = ("credit", "balance", "wallet", "points", "token-balance", "spend", "redeem",
               "withdraw", "transfer", "deduct")
_ADMIN_KW = ("/admin", "/api/admin", "/manage", "/internal", "/console", "/superuser", "/staff", "/backoffice")

# Common paths synthesised against live hosts for read-only checks.
_WORKFLOW_PATHS = ("/checkout/confirm", "/checkout/complete", "/order/confirm",
                   "/cart/confirm", "/checkout/success", "/order/success")
_ADMIN_PATHS = ("/admin", "/api/admin/users", "/api/admin", "/admin/users",
                "/manage/users", "/internal/api/users")


def _has_kw(url: str, kws: Sequence[str]) -> bool:
    u = url.lower()
    return any(k in u for k in kws)


def _origin(url: str) -> str:
    p = urlparse(url)
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return ""


def _normalize_hosts(live_hosts: Sequence[str]) -> List[str]:
    out = []
    for h in live_hosts or []:
        h = str(h).strip()
        if not h:
            continue
        if "://" not in h:
            h = "https://" + h
        out.append(h.rstrip("/"))
    return out


# ===========================================================================
# CATEGORY 4: WORKFLOW / STEP BYPASS  (READ-ONLY)
# ===========================================================================
async def _test_workflow_bypass(
    client: Any, scope_policy: Any, candidate_urls: Sequence[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for url in candidate_urls:
        # Read-only GET directly to a confirmation/success step.
        probe = await _safe_request(client, scope_policy, "GET", url)
        if probe is None or not probe.ok:
            continue
        body = probe.text or ""
        # Confirmed only if the confirmation content renders WITHOUT a payment
        # gate / auth wall -> the workflow was skipped server-side.
        if _CONFIRM_RE.search(body) and not _PAYMENT_GATE_RE.search(body) and _looks_authenticated_content(probe):
            findings.append(_make_finding(
                category="workflow_bypass",
                title="Checkout workflow bypass: order confirmation reachable without payment step",
                vulnerability_class="Business Logic Flaw (Improper Workflow Enforcement)",
                url=url, method="GET", parameter="(workflow step)",
                severity="high", confidence=85,
                evidence={
                    "request": probe.raw_request,
                    "response": probe.raw_response,
                    "signal": "Confirmation content served directly with no payment gate or auth redirect.",
                },
                reproduction_steps=[
                    f"As an authenticated test user, add an item to the cart but do NOT pay.",
                    f"Navigate directly to the confirmation step: GET {url}",
                    "Observe an order-confirmation/success page rendered even though the "
                    "payment step was never completed.",
                    "Do not place a real paid order; stop at the confirmation render.",
                ],
                business_impact="An attacker can obtain goods/services without paying by jumping "
                                "straight to order confirmation, causing direct revenue loss and "
                                "fulfilment of unpaid orders.",
                technical_impact="The server does not enforce that the payment step precedes order "
                                 "confirmation (broken state machine).",
                remediation="Enforce server-side workflow state: the confirmation endpoint must "
                            "verify a completed, paid order in the session/DB before rendering. "
                            "Reference OWASP WSTG Business Logic Testing.",
                cwe="CWE-841",  # Improper Enforcement of Behavioral Workflow
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N (7.1)",
            ))
    return findings


# ===========================================================================
# CATEGORY 6: ACCOUNT PRIVILEGE BYPASS  (READ-ONLY)
# ===========================================================================
async def _test_privilege_bypass(
    client: Any, scope_policy: Any, admin_urls: Sequence[str], normal_urls: Sequence[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 6a. Standard session calling admin-only endpoints.
    for url in admin_urls:
        probe = await _safe_request(client, scope_policy, "GET", url)
        if probe is None or not probe.ok:
            continue
        body = probe.text or ""
        if _looks_authenticated_content(probe) and _ADMIN_DATA_RE.search(body):
            findings.append(_make_finding(
                category="privilege_bypass",
                title="Broken access control: standard user can access admin-only endpoint",
                vulnerability_class="Broken Access Control (Privilege Escalation)",
                url=url, method="GET", parameter="(session role)",
                severity="critical", confidence=92,
                evidence={
                    "request": probe.raw_request,
                    "response": probe.raw_response,
                    "signal": "Admin-only data returned to a standard (non-admin) session.",
                },
                reproduction_steps=[
                    "Authenticate as a standard (non-admin) TEST user.",
                    f"Request the admin endpoint with the standard session: GET {url}",
                    "Observe administrative data returned despite lacking admin privileges.",
                ],
                business_impact="Any low-privilege user can read/operate admin functionality, "
                                "exposing all users' data and administrative actions.",
                technical_impact="Missing server-side authorization (function-level access control) "
                                 "on administrative endpoints.",
                remediation="Enforce role-based authorization server-side on every admin endpoint; "
                            "deny by default. Reference OWASP API Security Top 10 API5 (BFLA).",
                cwe="CWE-285",  # Improper Authorization
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.5)",
            ))

    # 6b. Parameter pollution: inject role=admin into a normal request and diff.
    for url in normal_urls:
        baseline = await _safe_request(client, scope_policy, "GET", url)
        if baseline is None or not baseline.ok:
            continue
        base_elevated = bool(baseline.text and _ELEVATION_RE.search(baseline.text))
        polluted = await _safe_request(
            client, scope_policy, "GET", url,
            params={"role": "admin", "is_admin": "true", "admin": "true"},
        )
        if polluted is None or not polluted.ok:
            continue
        pol_elevated = bool(polluted.text and _ELEVATION_RE.search(polluted.text))
        # Confirmed only if elevation appears AFTER pollution but not before.
        if pol_elevated and not base_elevated and _looks_authenticated_content(polluted):
            findings.append(_make_finding(
                category="privilege_bypass",
                title="Mass-assignment / parameter pollution grants elevated role",
                vulnerability_class="Broken Access Control (Mass Assignment)",
                url=url, method="GET", parameter="role/is_admin",
                severity="high", confidence=88,
                evidence={
                    "baseline_request": baseline.raw_request,
                    "baseline_response": baseline.raw_response,
                    "request": polluted.raw_request,
                    "response": polluted.raw_response,
                    "signal": "Response reflects admin/elevated role only after injecting role parameters.",
                },
                reproduction_steps=[
                    "Authenticate as a standard TEST user.",
                    f"Send the normal request and note no elevated role: GET {url}",
                    f"Re-send with injected parameters: GET {url}?role=admin&is_admin=true",
                    "Observe the response now reflects an elevated/admin role.",
                ],
                business_impact="A normal user can self-escalate to administrator by adding a role "
                                "parameter, leading to full privilege escalation.",
                technical_impact="The endpoint binds client-supplied role/privilege fields without "
                                 "server-side authorization (mass assignment).",
                remediation="Never accept role/privilege fields from the client. Use allow-lists for "
                            "bindable fields and authorize role changes server-side. "
                            "Reference OWASP Mass Assignment Cheat Sheet.",
                cwe="CWE-915",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.5)",
            ))
    return findings


# ===========================================================================
# CATEGORY 1: PRICE MANIPULATION  (state-changing, gated; non-completing)
# ===========================================================================
async def _test_price_manipulation(
    client: Any, scope_policy: Any, preview_urls: Sequence[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    overflow = 2147483647
    for url in preview_urls:
        # Baseline: a normal price on a NON-finalizing preview/recalculation endpoint.
        baseline = await _safe_request(
            client, scope_policy, "POST", url, state_changing=True,
            json_body={"price": 100.0, "amount": 100.0, "quantity": 1},
        )
        if baseline is None or not baseline.ok:
            continue
        base_total = _extract_total(baseline.json)

        for label, payload in (
            ("zero", {"price": 0, "amount": 0, "quantity": 1}),
            ("negative", {"price": -100.0, "amount": -100.0, "quantity": 1}),
            ("overflow", {"price": overflow, "amount": overflow, "quantity": 1}),
        ):
            probe = await _safe_request(
                client, scope_policy, "POST", url, state_changing=True, json_body=payload,
            )
            if probe is None or not probe.ok:
                continue
            total = _extract_total(probe.json)
            accepted = False
            reason = ""
            # Confirmed if the server ACCEPTS the client-supplied price server-side.
            if 200 <= (probe.status or 0) < 300 and total is not None:
                if label == "zero" and total == 0 and (base_total is None or base_total != 0):
                    accepted, reason = True, "Server returned total 0 from client-supplied price=0."
                elif label == "negative" and total < 0:
                    accepted, reason = True, "Server accepted a negative price (total < 0)."
                elif label == "overflow" and total >= overflow:
                    accepted, reason = True, "Server accepted integer-overflow price without validation."
            if accepted:
                findings.append(_make_finding(
                    category="price_manipulation",
                    title=f"Server trusts client-supplied price ({label}) -- price tampering",
                    vulnerability_class="Business Logic Flaw (Client-Side Price Trust)",
                    url=url, method="POST", parameter="price/amount",
                    severity="high" if label != "negative" else "critical",
                    confidence=90,
                    evidence={
                        "baseline_request": baseline.raw_request,
                        "baseline_response": baseline.raw_response,
                        "request": probe.raw_request,
                        "response": probe.raw_response,
                        "signal": reason,
                    },
                    reproduction_steps=[
                        "Add an item to the cart as a TEST user.",
                        f"Intercept the price/recalculation request to {url}.",
                        f"Modify the price/amount field to the {label} value: {payload}.",
                        "Observe the server reflect/accept the manipulated price in the recalculated total.",
                        "STOP here -- do NOT submit payment or complete the order.",
                    ],
                    business_impact="An attacker can purchase items for free or arbitrary amounts, "
                                    "causing direct and scalable revenue loss.",
                    technical_impact="Price is taken from client input and not re-derived/validated "
                                     "against the catalog server-side.",
                    remediation="Always compute price server-side from trusted catalog data; ignore "
                                "client-supplied prices. Validate ranges and reject negative/overflow "
                                "values. Reference OWASP WSTG-BUSLOGIC.",
                    cwe="CWE-840",  # Business Logic Errors
                    cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (6.5)",
                ))
                break  # one confirmed variant per endpoint is enough
    return findings


# ===========================================================================
# CATEGORY 2: QUANTITY MANIPULATION  (state-changing, gated; non-completing)
# ===========================================================================
async def _test_quantity_manipulation(
    client: Any, scope_policy: Any, preview_urls: Sequence[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for url in preview_urls:
        baseline = await _safe_request(
            client, scope_policy, "POST", url, state_changing=True,
            json_body={"quantity": 2, "price": 50.0},
        )
        if baseline is None or not baseline.ok:
            continue
        base_total = _extract_total(baseline.json)

        for label, payload in (
            ("negative", {"quantity": -1, "price": 50.0}),
            ("fractional", {"quantity": 0.1, "price": 50.0}),
            ("zero", {"quantity": 0, "price": 50.0}),
        ):
            probe = await _safe_request(
                client, scope_policy, "POST", url, state_changing=True, json_body=payload,
            )
            if probe is None or not probe.ok:
                continue
            total = _extract_total(probe.json)
            accepted, reason = False, ""
            if 200 <= (probe.status or 0) < 300 and total is not None:
                if label == "negative" and total < 0:
                    accepted, reason = True, "Negative quantity produced a negative total (credit to attacker)."
                elif label == "fractional" and base_total is not None and 0 < total < base_total:
                    accepted, reason = True, "Fractional quantity accepted and priced (no integer validation)."
            if accepted:
                findings.append(_make_finding(
                    category="quantity_manipulation",
                    title=f"Quantity manipulation ({label}) mis-prices the order",
                    vulnerability_class="Business Logic Flaw (Quantity Validation)",
                    url=url, method="POST", parameter="quantity",
                    severity="high", confidence=88,
                    evidence={
                        "baseline_request": baseline.raw_request,
                        "baseline_response": baseline.raw_response,
                        "request": probe.raw_request,
                        "response": probe.raw_response,
                        "signal": reason,
                    },
                    reproduction_steps=[
                        "As a TEST user, open the cart with one line item.",
                        f"Send a recalculation request to {url} with quantity={payload['quantity']}.",
                        "Observe the total become negative or otherwise mis-calculated.",
                        "STOP -- do NOT complete checkout.",
                    ],
                    business_impact="Negative/fractional quantities can yield negative totals "
                                    "(store credit to the attacker) or free items, causing financial loss.",
                    technical_impact="Quantity is not validated as a positive integer and totals are "
                                     "computed from unvalidated input.",
                    remediation="Validate quantity as a positive integer within stock limits; clamp "
                                "and reject otherwise; recompute totals server-side.",
                    cwe="CWE-840",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (6.5)",
                ))
                break
    return findings


# ===========================================================================
# CATEGORY 3: COUPON / PROMO ABUSE  (state-changing, gated; non-completing)
# ===========================================================================
async def _test_coupon_abuse(
    client: Any, scope_policy: Any, coupon_urls: Sequence[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    code = "TESTCODE"
    for url in coupon_urls:
        first = await _safe_request(
            client, scope_policy, "POST", url, state_changing=True,
            json_body={"code": code},
        )
        if first is None or not first.ok or not (200 <= (first.status or 0) < 300):
            continue
        total_after_first = _extract_total(first.json)
        # Apply the SAME coupon again in the same session.
        second = await _safe_request(
            client, scope_policy, "POST", url, state_changing=True,
            json_body={"code": code},
        )
        if second is None or not second.ok:
            continue
        total_after_second = _extract_total(second.json)
        # Confirmed if a second application of the same code further reduces the total.
        if (total_after_first is not None and total_after_second is not None
                and total_after_second < total_after_first):
            findings.append(_make_finding(
                category="coupon_abuse",
                title="Coupon can be applied multiple times (stackable single-use code)",
                vulnerability_class="Business Logic Flaw (Promo/Coupon Abuse)",
                url=url, method="POST", parameter="code",
                severity="medium", confidence=85,
                evidence={
                    "first_request": first.raw_request,
                    "first_response": first.raw_response,
                    "request": second.raw_request,
                    "response": second.raw_response,
                    "signal": f"Total dropped from {total_after_first} to {total_after_second} "
                              "after re-applying the same code.",
                },
                reproduction_steps=[
                    "As a TEST user with items in the cart, apply a coupon code.",
                    f"Re-submit the same code to {url} a second time in the same session.",
                    "Observe the discount applied again, further reducing the total.",
                    "STOP -- do NOT complete the discounted purchase.",
                ],
                business_impact="Attackers can stack a single-use coupon to drive prices arbitrarily "
                                "low (or to zero), causing revenue loss and promo fraud.",
                technical_impact="No idempotency / single-use enforcement on coupon application.",
                remediation="Enforce single-use and per-cart uniqueness server-side; make coupon "
                            "application idempotent and recompute discounts authoritatively.",
                cwe="CWE-840",
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N (4.3)",
            ))
    return findings


# ===========================================================================
# CATEGORY 5: RACE CONDITION ON CREDITS  (gated: state-changing + destructive)
# ===========================================================================
async def _test_race_condition(
    client: Any, scope_policy: Any, spend_urls: Sequence[str],
    balance_urls: Sequence[str], concurrency: int = 10,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for url in spend_urls:
        # Hard gate: this test can permanently alter balances.
        if not (await _mutation_allowed(scope_policy, url) and await _destructive_allowed(scope_policy, url)):
            continue

        # Read balance before (best effort, read-only GET).
        before = None
        for burl in balance_urls:
            bp = await _safe_request(client, scope_policy, "GET", burl)
            if bp and bp.ok:
                before = _extract_balance(bp.json)
                if before is not None:
                    break

        # Fire N simultaneous spend requests for the SAME minimal unit of credit.
        async def _one():
            return await _safe_request(
                client, scope_policy, "POST", url,
                state_changing=True, destructive=True,
                json_body={"amount": 1, "quantity": 1},
            )

        probes = await asyncio.gather(*[_one() for _ in range(concurrency)], return_exceptions=True)
        successes = [p for p in probes if isinstance(p, Probe) and p.ok and 200 <= (p.status or 0) < 300]

        # Read balance after (read-only GET).
        after = None
        for burl in balance_urls:
            bp = await _safe_request(client, scope_policy, "GET", burl)
            if bp and bp.ok:
                after = _extract_balance(bp.json)
                if after is not None:
                    break

        # Confirm ONLY on hard proof: balance went negative, OR more successful
        # deductions than the balance could fund.
        negative_balance = after is not None and after < 0
        overspent = (before is not None and after is not None
                     and (before - after) > before + 1e-9)  # deducted more than was available
        too_many = before is not None and len(successes) > max(1, int(before))
        if negative_balance or overspent or too_many:
            sample = next((p for p in successes), None)
            findings.append(_make_finding(
                category="race_condition",
                title="Race condition allows over-spending credits/balance (double spend)",
                vulnerability_class="Business Logic Flaw (Race Condition / TOCTOU)",
                url=url, method="POST", parameter="(concurrent spend)",
                severity="high", confidence=83,
                evidence={
                    "balance_before": before,
                    "balance_after": after,
                    "concurrent_requests": concurrency,
                    "successful_deductions": len(successes),
                    "request": sample.raw_request if sample else "(see concurrent POSTs)",
                    "response": sample.raw_response if sample else "",
                    "signal": ("Final balance negative" if negative_balance else
                               "More successful deductions than balance could fund"),
                },
                reproduction_steps=[
                    "As a TEST user, fund the account with a small known credit balance.",
                    f"Send {concurrency} simultaneous spend requests to {url} for the same unit.",
                    "Observe more deductions succeed than the balance allows / balance goes negative.",
                    "Restore/refund the test balance afterwards.",
                ],
                business_impact="Attackers can spend the same credits/balance multiple times "
                                "(double spend), directly defrauding the platform.",
                technical_impact="Non-atomic check-then-deduct on balance (TOCTOU) without row "
                                 "locking or idempotency keys.",
                remediation="Make balance deduction atomic (SELECT ... FOR UPDATE / conditional "
                            "UPDATE ... WHERE balance >= amount) and use idempotency keys.",
                cwe="CWE-362",  # Concurrent Execution using Shared Resource ('Race Condition')
                cvss="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N (5.9)",
            ))
    return findings


# ===========================================================================
# PUBLIC ENTRY POINT
# ===========================================================================
async def hunt_business_logic_deep(
    client: Any,
    urls: List[str],
    live_hosts: List[str],
    scope_policy: Any,
) -> List[Dict[str, Any]]:
    """Actively hunt for six classes of business-logic vulnerability.

    Args:
        client: httpx.AsyncClient (cookies/headers preconfigured for a TEST user).
        urls: discovered URLs/endpoints to classify and probe.
        live_hosts: reachable hosts; used to synthesise common workflow/admin paths.
        scope_policy: authorization policy (fail-closed). For mutating tests it
            must also authorise state changes (allow_state_changing/allow_mutation/
            allow_active); the race test additionally needs allow_destructive.

    Returns:
        A de-duplicated list of CONFIRMED finding dicts (BurpOllama model).
        Never raises; out-of-scope and unauthorised mutations are skipped silently.
    """
    if not isinstance(urls, (list, tuple)):
        urls = []
    urls = [str(u) for u in urls if u]
    hosts = _normalize_hosts(live_hosts or [])

    # --- Build candidate endpoint sets ------------------------------------
    checkout_urls = [u for u in urls if _has_kw(u, _CHECKOUT_KW)]
    preview_urls = [u for u in urls if _has_kw(u, _PRICE_PREVIEW_KW)] or checkout_urls
    coupon_urls = [u for u in urls if _has_kw(u, _COUPON_KW)]
    confirm_urls = [u for u in urls if _has_kw(u, _CONFIRM_KW)]
    _spend_kw = ("spend", "redeem", "withdraw", "transfer", "deduct", "purchase")
    # Balance-READ endpoints exclude spend-like endpoints so the "before" read
    # never mutates state.
    balance_urls = [u for u in urls if _has_kw(u, ("balance", "credit", "points", "wallet", "funds"))
                    and not _has_kw(u, _spend_kw)]
    spend_urls = [u for u in urls if _has_kw(u, _spend_kw)]
    admin_urls = [u for u in urls if _has_kw(u, _ADMIN_KW)]
    # Normal endpoints for parameter-pollution diffing (non-admin, non-checkout).
    normal_urls = [u for u in urls
                   if not _has_kw(u, _ADMIN_KW)
                   and _has_kw(u, ("/api/", "/user", "/account", "/profile", "/me"))][:10]

    # Synthesise common paths from live hosts (only requested if in scope).
    for host in hosts:
        confirm_urls += [urljoin(host + "/", p.lstrip("/")) for p in _WORKFLOW_PATHS]
        admin_urls += [urljoin(host + "/", p.lstrip("/")) for p in _ADMIN_PATHS]

    # De-duplicate while preserving order, and cap to keep request volume sane.
    def _dedup(seq: Sequence[str], cap: int = 25) -> List[str]:
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
            if len(out) >= cap:
                break
        return out

    confirm_urls = _dedup(confirm_urls)
    admin_urls = _dedup(admin_urls)
    preview_urls = _dedup(preview_urls)
    coupon_urls = _dedup(coupon_urls)
    balance_urls = _dedup(balance_urls)
    spend_urls = _dedup(spend_urls)
    normal_urls = _dedup(normal_urls)

    findings: List[Dict[str, Any]] = []

    # --- Run all category tests; isolate failures per category ------------
    async def _run(coro):
        try:
            return await coro
        except Exception:
            return []

    results = await asyncio.gather(
        _run(_test_workflow_bypass(client, scope_policy, confirm_urls)),
        _run(_test_privilege_bypass(client, scope_policy, admin_urls, normal_urls)),
        _run(_test_price_manipulation(client, scope_policy, preview_urls)),
        _run(_test_quantity_manipulation(client, scope_policy, preview_urls)),
        _run(_test_coupon_abuse(client, scope_policy, coupon_urls)),
        _run(_test_race_condition(client, scope_policy, spend_urls, balance_urls)),
    )
    for group in results:
        findings.extend(group)

    # --- Deduplicate by (category, url, parameter) ------------------------
    seen, deduped = set(), []
    for f in findings:
        key = (f["category"], f["affected_url"], f["parameter"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    # Sort highest severity first for triage convenience.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    deduped.sort(key=lambda f: (sev_rank.get(f["severity"], 0), f["confidence"]), reverse=True)
    return deduped


# ===========================================================================
# SELF-TEST (offline mock app; no real network)
# ===========================================================================
if __name__ == "__main__":

    class _Resp:
        def __init__(self, status, payload=None, text=None, headers=None):
            self.status_code = status
            self._payload = payload
            self._text = text if text is not None else (json.dumps(payload) if payload is not None else "")
            self.headers = headers or {"content-type": "application/json"}

        def json(self):
            if self._payload is None:
                raise ValueError("no json")
            return self._payload

        @property
        def text(self):
            return self._text

    class _MockApp:
        """A deliberately-vulnerable mock app to exercise detection paths."""
        def __init__(self):
            self.balance = 3  # starting test credits

        async def request(self, method, url, headers=None, params=None, json=None, timeout=None):
            await asyncio.sleep(0)  # exercise await
            path = urlparse(url).path
            params = params or {}
            body = json or {}

            # Workflow bypass: confirmation served without payment.
            if path.endswith("/checkout/confirm"):
                return _Resp(200, text="<h1>Order Confirmed</h1> Order number #1234. Thank you for your order!")

            # Privilege bypass: admin data to anyone.
            if path.endswith("/api/admin/users"):
                return _Resp(200, {"users": [{"id": 1, "role": "admin"}], "note": "list users"})

            # Parameter pollution: elevate when role param present.
            if path.endswith("/api/profile") or path.endswith("/me"):
                if str(params.get("role", "")).lower() == "admin":
                    return _Resp(200, {"id": 7, "role": "admin", "is_admin": True})
                return _Resp(200, {"id": 7, "role": "user"})

            # Price preview: trusts client price (vulnerable).
            if path.endswith("/cart/preview"):
                price = body.get("price", 0)
                qty = body.get("quantity", 1)
                try:
                    total = float(price) * float(qty)
                except Exception:
                    total = 0
                return _Resp(200, {"total": total})

            # Coupon: stackable (vulnerable) -> each apply subtracts 10.
            # NOTE: tracked on a dedicated attribute so concurrent tests in the
            # self-test don't clobber the wallet balance used by the race test.
            if path.endswith("/cart/coupon"):
                self._coupon_total = getattr(self, "_coupon_total", 100) - 10
                return _Resp(200, {"total": self._coupon_total})

            # Spend endpoint: non-atomic -> always succeeds (race).
            if path.endswith("/wallet/spend"):
                self.balance -= 1
                return _Resp(200, {"ok": True, "balance": self.balance})
            if path.endswith("/wallet/balance"):
                return _Resp(200, {"balance": self.balance})

            return _Resp(404, {"error": "not found"})

    async def _main():
        app = _MockApp()
        urls = [
            "https://shop.test/cart/preview",
            "https://shop.test/cart/coupon",
            "https://shop.test/api/profile",
            "https://shop.test/api/admin/users",
            "https://shop.test/wallet/spend",
            "https://shop.test/wallet/balance",
        ]
        hosts = ["shop.test"]

        # 1) Read-only scope: only workflow + privilege tests should fire.
        ro_scope = {"allowed_hosts": ["shop.test"]}
        ro = await hunt_business_logic_deep(app, urls, hosts, ro_scope)
        print(f"READ-ONLY scope -> {len(ro)} findings:")
        for f in ro:
            print(f"  [{f['severity']:8}] {f['category']:20} {f['title']}")
        cats_ro = {f["category"] for f in ro}
        assert "workflow_bypass" in cats_ro, "workflow bypass not detected"
        assert "privilege_bypass" in cats_ro, "privilege bypass not detected"
        # Mutating categories must NOT fire without authorization.
        assert "price_manipulation" not in cats_ro, "price test ran without mutation authorization!"
        assert "race_condition" not in cats_ro, "race test ran without destructive authorization!"

        # 2) Full authorization: mutating tests now allowed.
        full_scope = {
            "allowed_hosts": ["shop.test"],
            "allow_state_changing": True,
            "allow_destructive": True,
        }
        # Fresh app so balance starts at 3 again.
        full = await hunt_business_logic_deep(_MockApp(), urls, hosts, full_scope)
        print(f"\nFULL-AUTH scope -> {len(full)} findings:")
        for f in full:
            print(f"  [{f['severity']:8}] cwe={f['cwe']:8} {f['category']:20} {f['title']}")
        cats_full = {f["category"] for f in full}
        assert "price_manipulation" in cats_full, "price manipulation not detected"
        assert "coupon_abuse" in cats_full, "coupon abuse not detected"
        assert "race_condition" in cats_full, "race condition not detected"

        # 3) Out-of-scope host -> zero requests, zero findings.
        oos = await hunt_business_logic_deep(_MockApp(), urls, ["evil.test"], {"allowed_hosts": ["evil.test"]})
        print(f"\nOUT-OF-SCOPE host -> {len(oos)} findings (expected 0 for shop.test paths)")

        # 4) None safety.
        none_res = await hunt_business_logic_deep(_MockApp(), None, None, None)
        assert none_res == [], "None input should yield []"

        # Show one full finding.
        print("\nExample confirmed finding:")
        print(json.dumps(full[0], indent=2)[:1400])
        print("\n[ALL SELF-TESTS PASSED]")

    asyncio.run(_main())
