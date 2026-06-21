"""fp_eliminator.py

False-positive elimination for vulnerability findings.

    eliminate_false_positives(findings, tech_stack, scan_context) -> dict

Applies deterministic FP rules per vulnerability class and re-labels each
finding's `exploitability_status` (finding_model.py format) as one of:

    CONFIRMED       -- no FP rule applies; treat as a real bug
    CANDIDATE       -- 1-2 SOFT FP indicators; needs a human/second look
    FALSE_POSITIVE  -- a HARD FP rule fired (or 3+ soft indicators)

RULE STRENGTH MODEL
  * HARD rule  -> proves the finding is NOT exploitable in this context
                  => immediate FALSE_POSITIVE.
  * SOFT rule  -> raises uncertainty but is not dispositive
                  => 1-2 soft => CANDIDATE; 3+ soft => FALSE_POSITIVE.

A rule only fires when the deciding signal is actually present in the finding,
its `evidence`, or `scan_context`. Missing signals never fabricate an FP, so we
do not eliminate findings we cannot disprove (controls false negatives).

EVIDENCE SCHEMA (all optional; read from finding, finding["evidence"], or
scan_context). Representative keys this engine understands:

  XSS:      reflection_context ("js_string_html_encoded"|"comment_node"|
            "html_body"|"html_attribute"|...), content_type, response_headers,
            sandboxed_iframe (bool)
  SQLi:     error_source ("input_validation"|"database"), detection
            ("error-based"|"time-based"|...), injected_seconds, baseline_seconds,
            time_delay_seconds, page_type ("documentation"|"tutorial"|...),
            error_in_baseline (bool)
  IDOR:     same_data (bool), same_user_id (bool), public_data_for_all_ids
            (bool), diff_only_timestamps (bool), empty_for_all_ids (bool)
  SSRF:     url_validated_allowlist (bool), all_external_blocked (bool),
            oob_confirmed (bool)
  Redirect: redirect_same_domain (bool), location_relative (bool),
            destination_validated (bool)
  Headers:  is_static_asset (bool) | content_type | url extension,
            status_code, is_error_page (bool)
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ===========================================================================
# STATUS CONSTANTS (finding_model.py exploitability_status values)
# ===========================================================================
CONFIRMED = "CONFIRMED"
CANDIDATE = "CANDIDATE"
FALSE_POSITIVE = "FALSE_POSITIVE"

# Tier ordering for upgrade/downgrade accounting (higher = more real).
_TIER = {FALSE_POSITIVE: 0, CANDIDATE: 1, CONFIRMED: 2}

# Map varied input statuses to a starting tier.
_INPUT_STATUS_TIER = {
    "confirmed": CONFIRMED,
    "pass": CONFIRMED,
    "true_positive": CONFIRMED,
    "probable": CANDIDATE,
    "candidate": CANDIDATE,
    "downgrade": CANDIDATE,
    "not_vulnerable": FALSE_POSITIVE,
    "false_positive": FALSE_POSITIVE,
    "kill": FALSE_POSITIVE,
}

# How many soft indicators tip a finding from CANDIDATE into FALSE_POSITIVE.
_SOFT_FP_THRESHOLD = 3


# ===========================================================================
# SIGNAL ACCESS (None-safe, searches finding + evidence + scan_context)
# ===========================================================================
class _Signals:
    """Lookup helper that searches a finding, its evidence, and scan_context."""

    def __init__(self, finding: Dict[str, Any], scan_context: Dict[str, Any]) -> None:
        self.finding = finding if isinstance(finding, dict) else {}
        self.evidence = self.finding.get("evidence") if isinstance(self.finding.get("evidence"), dict) else {}
        self.scan = scan_context if isinstance(scan_context, dict) else {}

    def get(self, *keys: str, default: Any = None) -> Any:
        for store in (self.finding, self.evidence, self.scan):
            for k in keys:
                if k in store and store[k] is not None:
                    return store[k]
        return default

    def flag(self, *keys: str) -> bool:
        """True only if a recognised truthy value is present for any key."""
        val = self.get(*keys, default=None)
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.strip().lower() in {"true", "yes", "1"}
        if isinstance(val, (int, float)):
            return val == 1
        return False

    def headers(self) -> Dict[str, str]:
        h = self.get("response_headers", "headers", default={})
        if isinstance(h, dict):
            return {str(k).lower(): str(v) for k, v in h.items()}
        return {}

    def header(self, name: str) -> Optional[str]:
        return self.headers().get(name.lower())

    def content_type(self) -> str:
        ct = self.get("content_type", "response_content_type", "contentType", default="")
        if not ct:
            ct = self.header("content-type") or ""
        return str(ct).lower()

    def url(self) -> str:
        return str(self.get("affected_url", "url", "target", default="") or "")

    def status_code(self) -> Optional[int]:
        val = self.get("status_code", "status", "response_status", default=None)
        try:
            return int(val) if val is not None else None
        except (TypeError, ValueError):
            return None


# ===========================================================================
# CATEGORY DETECTION
# ===========================================================================
_STATIC_EXT = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
               ".mp4", ".webm", ".pdf")

_HEADER_TOKENS = ("security header", "missing header", "content-security-policy",
                  "content security policy", "csp", "hsts", "strict-transport",
                  "x-frame-options", "clickjack", "x-content-type-options",
                  "referrer-policy", "permissions-policy", "x-xss-protection")


def _categories(finding: Dict[str, Any]) -> List[str]:
    """Return the FP rule-sets applicable to this finding."""
    text = " ".join(str(finding.get(k, "")) for k in
                    ("vulnerability_class", "vuln_type", "type", "title", "category", "cwe")).lower()
    tags = finding.get("tags")
    if isinstance(tags, (list, tuple)):
        text += " " + " ".join(str(t).lower() for t in tags)

    cats: List[str] = []
    if "xss" in text or "cross-site scripting" in text or "cross site scripting" in text:
        cats.append("xss")
    if "sqli" in text or "sql injection" in text:
        cats.append("sqli")
    if "idor" in text or "bola" in text or "insecure direct object" in text or "object level authorization" in text:
        cats.append("idor")
    if "ssrf" in text or "server-side request forgery" in text or "server side request forgery" in text:
        cats.append("ssrf")
    if "open redirect" in text or ("redirect" in text and "open" in text) or "unvalidated redirect" in text:
        cats.append("open_redirect")
    if any(tok in text for tok in _HEADER_TOKENS):
        cats.append("security_header")
    return cats


# A rule result is (strength, reason): strength in {"HARD","SOFT"}.
Rule = Tuple[str, str]


# ===========================================================================
# XSS FP RULES
# ===========================================================================
def _rules_xss(s: _Signals) -> List[Rule]:
    out: List[Rule] = []
    ctx = str(s.get("reflection_context", "xss_context", default="")).lower()

    if ctx in {"js_string_html_encoded", "javascript_string_encoded"} or \
       (("js" in ctx or "javascript" in ctx) and ("encoded" in ctx or "html-encoded" in ctx)):
        out.append(("HARD", "Reflection is inside a JS string that is HTML-encoded before DOM insertion; "
                            "the payload cannot break out to execute."))
    if ctx in {"comment_node", "html_comment", "comment"}:
        out.append(("HARD", "Payload appears only inside an HTML comment node; it is not parsed as active markup."))

    ct = s.content_type()
    if ct.startswith("application/json"):
        out.append(("HARD", "Response Content-Type is application/json (not text/html); the browser will not "
                            "render the reflection as HTML."))
    nosniff = (s.header("x-content-type-options") or "").lower()
    if "nosniff" in nosniff and ct and not ct.startswith("text/html"):
        out.append(("HARD", "X-Content-Type-Options: nosniff is set and the content type is not HTML; "
                            "MIME sniffing to HTML is blocked."))
    if s.flag("sandboxed_iframe") or "sandbox" in ctx:
        out.append(("HARD", "Reflection renders inside a sandboxed iframe (no script execution context)."))
    return out


# ===========================================================================
# SQLi FP RULES
# ===========================================================================
def _rules_sqli(s: _Signals) -> List[Rule]:
    out: List[Rule] = []

    if str(s.get("error_source", default="")).lower() in {"input_validation", "validation", "app_validation"}:
        out.append(("HARD", "Error message originates from application input validation, not the database engine."))

    if s.flag("error_in_baseline"):
        out.append(("HARD", "The 'SQL error' appears even in a clean baseline request; it is not injection-induced."))

    page_type = str(s.get("page_type", default="")).lower()
    if page_type in {"documentation", "docs", "tutorial", "blog", "help"} or s.flag("sql_error_in_doc"):
        out.append(("HARD", "The SQL-error string appears in documentation/tutorial content, not a live query error."))

    # Time-based: compare injected delay against baseline.
    detection = str(s.get("detection", "method", "vuln_type", default="")).lower()
    injected = _num(s.get("injected_seconds", "time_delay_seconds", "delay_seconds"))
    baseline = _num(s.get("baseline_seconds", "baseline_time"))
    is_time_based = "time" in detection or injected is not None
    if is_time_based and injected is not None and baseline is not None and baseline > 0:
        ratio = injected / baseline
        if ratio < 2.0:
            out.append(("HARD", f"Time delay ({injected:.2f}s) is < 2x baseline ({baseline:.2f}s); "
                                "consistent with network jitter, not an injected delay."))
        elif ratio < 3.0:
            out.append(("SOFT", f"Time delay ({injected:.2f}s) is only {ratio:.1f}x baseline; borderline "
                                "for a reliable time-based signal."))
    return out


# ===========================================================================
# IDOR FP RULES
# ===========================================================================
def _rules_idor(s: _Signals) -> List[Rule]:
    out: List[Rule] = []
    if s.flag("same_data") or s.flag("same_user_id") or s.flag("identical_response"):
        out.append(("HARD", "Both requests returned the same data / same user id; no cross-user access occurred."))
    if s.flag("public_data_for_all_ids") or s.flag("public_resource"):
        out.append(("HARD", "Endpoint returns public data for every id; access is by design, not an IDOR."))
    if s.flag("diff_only_timestamps") or s.flag("diff_only_counters"):
        out.append(("HARD", "The only differences between responses are timestamps/counters, not sensitive data."))
    if s.flag("empty_for_all_ids") or s.flag("empty_response"):
        out.append(("HARD", "Response is empty for all tested ids; no data is disclosed."))
    return out


# ===========================================================================
# SSRF FP RULES
# ===========================================================================
def _rules_ssrf(s: _Signals) -> List[Rule]:
    out: List[Rule] = []
    if s.flag("url_validated_allowlist") or s.flag("allowlist_validated"):
        out.append(("HARD", "The URL parameter is validated against an allowlist; attacker URLs are rejected."))
    if s.flag("all_external_blocked"):
        out.append(("HARD", "All external URLs return the same blocked response; outbound requests are not honoured."))
    # Lack of OOB confirmation is uncertainty, not proof of non-exploitability.
    if not s.flag("oob_confirmed") and not s.flag("direct_response_proof"):
        out.append(("SOFT", "No out-of-band (OOB) confirmation that the server made the request; unproven blind SSRF."))
    return out


# ===========================================================================
# OPEN REDIRECT FP RULES
# ===========================================================================
def _rules_open_redirect(s: _Signals) -> List[Rule]:
    out: List[Rule] = []
    if s.flag("redirect_same_domain") or s.flag("same_origin_redirect"):
        out.append(("HARD", "Redirect destination is the same domain; no off-site redirection is possible."))
    # Inspect the Location header if available.
    location = s.header("location") or str(s.get("location", "redirect_location", default="") or "")
    if s.flag("location_relative") or (location and location.startswith("/") and "//" not in location[:2]):
        out.append(("HARD", "Location header is a relative path (not an absolute external URL); not an open redirect."))
    if s.flag("destination_validated") or s.flag("redirect_destination_validated"):
        out.append(("HARD", "Redirect destination is validated against an allowlist."))
    return out


# ===========================================================================
# SECURITY HEADER FP RULES
# ===========================================================================
def _rules_security_header(s: _Signals) -> List[Rule]:
    out: List[Rule] = []
    url = s.url().lower().split("?")[0]
    ct = s.content_type()
    if s.flag("is_static_asset") or url.endswith(_STATIC_EXT) or \
       ct.startswith(("image/", "font/", "text/css", "application/javascript",
                      "text/javascript", "application/font")):
        out.append(("HARD", "Target is a static asset (image/CSS/JS/font); security headers are not security-relevant here."))
    status = s.status_code()
    if status is not None and 300 <= status < 400:
        out.append(("HARD", "Page returns a 3xx redirect; the missing-header check does not apply to redirect responses."))
    if s.flag("is_error_page") or (status is not None and status >= 400):
        out.append(("HARD", "Page is an error response; missing headers on error pages are not a meaningful finding."))
    return out


_CATEGORY_RULES = {
    "xss": _rules_xss,
    "sqli": _rules_sqli,
    "idor": _rules_idor,
    "ssrf": _rules_ssrf,
    "open_redirect": _rules_open_redirect,
    "security_header": _rules_security_header,
}


def _num(val: Any) -> Optional[float]:
    try:
        if val is None or isinstance(val, bool):
            return None
        return float(val)
    except (TypeError, ValueError):
        return None


# ===========================================================================
# PER-FINDING EVALUATION
# ===========================================================================
def _evaluate(finding: Dict[str, Any], scan_context: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
    """Return (new_status, hard_reasons, soft_reasons) for one finding."""
    s = _Signals(finding, scan_context)
    hard: List[str] = []
    soft: List[str] = []
    for cat in _categories(finding):
        rule_fn = _CATEGORY_RULES.get(cat)
        if not rule_fn:
            continue
        try:
            for strength, reason in rule_fn(s):
                (hard if strength == "HARD" else soft).append(f"[{cat}] {reason}")
        except Exception:
            # A malformed rule input must never abort evaluation.
            continue

    if hard:
        return FALSE_POSITIVE, hard, soft
    if len(soft) >= _SOFT_FP_THRESHOLD:
        return FALSE_POSITIVE, hard, soft
    if soft:
        return CANDIDATE, hard, soft
    return CONFIRMED, hard, soft


def _input_tier(finding: Dict[str, Any]) -> str:
    raw = str(finding.get("exploitability_status", "") or "").strip().lower()
    if raw in _INPUT_STATUS_TIER:
        return _INPUT_STATUS_TIER[raw]
    # A reported finding with no/odd status is assumed to start as CONFIRMED.
    return CONFIRMED


# ===========================================================================
# PUBLIC API
# ===========================================================================
def eliminate_false_positives(
    findings: List[Dict[str, Any]],
    tech_stack: List[str],
    scan_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Triage findings into confirmed / candidate / false-positive buckets.

    Args:
        findings: list of finding dicts (finding_model.py format).
        tech_stack: fingerprinted technologies (reserved for future stack-aware
            rules; accepted for API stability and may refine context).
        scan_context: shared scan-level signals (baseline timings, headers,
            flags) consulted when a finding omits a signal.

    Returns:
        {
          "confirmed":  [finding, ...],            # exploitability_status=CONFIRMED
          "candidates": [finding, ...],            # CANDIDATE (+ candidate_reasons)
          "false_positives": [finding, ...],       # FALSE_POSITIVE (+ fp_reason/fp_rules)
          "fp_rate": float,                         # % of findings eliminated
          "confidence_improvements": {
              "upgraded": int, "downgraded": int, "unchanged": int,
              "downgraded_to_candidate": int, "eliminated": int,
              "kept_confirmed": int
          }
        }

    Never raises: malformed findings are skipped per-item.
    """
    result: Dict[str, Any] = {
        "confirmed": [],
        "candidates": [],
        "false_positives": [],
        "fp_rate": 0.0,
        "confidence_improvements": {
            "upgraded": 0, "downgraded": 0, "unchanged": 0,
            "downgraded_to_candidate": 0, "eliminated": 0, "kept_confirmed": 0,
        },
    }
    if not isinstance(findings, (list, tuple)) or not findings:
        return result

    scan_context = scan_context if isinstance(scan_context, dict) else {}
    total = 0
    imp = result["confidence_improvements"]

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        total += 1
        finding = copy.deepcopy(raw)

        original_tier = _input_tier(finding)
        new_status, hard, soft = _evaluate(finding, scan_context)

        # Apply the new status to the finding.
        finding["exploitability_status"] = new_status

        if new_status == FALSE_POSITIVE:
            finding["fp_reason"] = hard[0] if hard else "Multiple soft FP indicators exceeded threshold."
            finding["fp_rules"] = hard if hard else soft
            finding["confidence"] = 0
            result["false_positives"].append(finding)
        elif new_status == CANDIDATE:
            finding["candidate_reasons"] = soft
            # Soften numeric confidence if present.
            conf = finding.get("confidence")
            if isinstance(conf, (int, float)) and not isinstance(conf, bool):
                finding["confidence"] = int(min(conf, 60))
            result["candidates"].append(finding)
        else:  # CONFIRMED
            result["confirmed"].append(finding)

        # --- Accounting: compare new tier vs original tier ----------------
        new_tier = new_status
        if _TIER[new_tier] < _TIER[original_tier]:
            imp["downgraded"] += 1
            if new_tier == CANDIDATE:
                imp["downgraded_to_candidate"] += 1
            if new_tier == FALSE_POSITIVE:
                imp["eliminated"] += 1
        elif _TIER[new_tier] > _TIER[original_tier]:
            imp["upgraded"] += 1
        else:
            imp["unchanged"] += 1
            if new_tier == CONFIRMED:
                imp["kept_confirmed"] += 1

        # Always reflect total eliminated count even if it equalled original tier.
        if new_tier == FALSE_POSITIVE and _TIER[new_tier] >= _TIER[original_tier]:
            imp["eliminated"] += 1

    result["fp_rate"] = round(100.0 * len(result["false_positives"]) / total, 1) if total else 0.0
    return result


# ===========================================================================
# SELF-TEST
# ===========================================================================
if __name__ == "__main__":
    import json

    findings = [
        # 1) XSS but JSON content-type -> HARD FP
        {"id": "X1", "vulnerability_class": "Reflected XSS", "exploitability_status": "confirmed",
         "evidence": {"content_type": "application/json", "reflection_context": "html_body"}},
        # 2) XSS genuinely in HTML body -> CONFIRMED
        {"id": "X2", "vulnerability_class": "Stored XSS", "exploitability_status": "confirmed",
         "evidence": {"content_type": "text/html", "reflection_context": "html_body"}},
        # 3) XSS reflected in HTML-encoded JS string -> HARD FP
        {"id": "X3", "vulnerability_class": "Reflected XSS", "exploitability_status": "confirmed",
         "evidence": {"content_type": "text/html", "reflection_context": "js_string_html_encoded"}},
        # 4) SQLi from input validation -> HARD FP
        {"id": "S1", "vulnerability_class": "SQL Injection", "exploitability_status": "confirmed",
         "evidence": {"error_source": "input_validation"}},
        # 5) SQLi time-based jitter (1.5x) -> HARD FP
        {"id": "S2", "vulnerability_class": "SQL Injection (time-based blind)", "exploitability_status": "probable",
         "evidence": {"detection": "time-based", "injected_seconds": 3.0, "baseline_seconds": 2.0}},
        # 6) SQLi time-based borderline (2.5x) -> CANDIDATE (soft)
        {"id": "S3", "vulnerability_class": "SQL Injection (time-based blind)", "exploitability_status": "confirmed",
         "evidence": {"detection": "time-based", "injected_seconds": 5.0, "baseline_seconds": 2.0}},
        # 7) SQLi confirmed error-based -> CONFIRMED
        {"id": "S4", "vulnerability_class": "SQL Injection", "exploitability_status": "confirmed",
         "evidence": {"error_source": "database", "detection": "error-based"}},
        # 8) IDOR same data -> HARD FP
        {"id": "I1", "vulnerability_class": "IDOR", "exploitability_status": "confirmed",
         "evidence": {"same_user_id": True}},
        # 9) IDOR diff only timestamps -> HARD FP
        {"id": "I2", "vulnerability_class": "IDOR", "exploitability_status": "confirmed",
         "evidence": {"diff_only_timestamps": True}},
        # 10) IDOR confirmed cross-user -> CONFIRMED
        {"id": "I3", "vulnerability_class": "IDOR", "exploitability_status": "confirmed",
         "evidence": {"same_user_id": False, "sensitive_fields_exposed": ["email"]}},
        # 11) SSRF allowlist -> HARD FP
        {"id": "F1", "vulnerability_class": "SSRF", "exploitability_status": "confirmed",
         "evidence": {"url_validated_allowlist": True}},
        # 12) SSRF blind no OOB -> CANDIDATE (soft)
        {"id": "F2", "vulnerability_class": "SSRF", "exploitability_status": "probable",
         "evidence": {"oob_confirmed": False}},
        # 13) SSRF with OOB -> CONFIRMED
        {"id": "F3", "vulnerability_class": "SSRF", "exploitability_status": "confirmed",
         "evidence": {"oob_confirmed": True}},
        # 14) Open redirect same domain -> HARD FP
        {"id": "R1", "vulnerability_class": "Open Redirect", "exploitability_status": "confirmed",
         "evidence": {"redirect_same_domain": True}},
        # 15) Open redirect relative location -> HARD FP
        {"id": "R2", "vulnerability_class": "Open Redirect", "exploitability_status": "confirmed",
         "evidence": {"location": "/dashboard"}},
        # 16) Security header on static asset -> HARD FP
        {"id": "H1", "vulnerability_class": "Missing Security Header (CSP)", "exploitability_status": "confirmed",
         "affected_url": "https://t/app.js", "evidence": {}},
        # 17) Security header on error page -> HARD FP
        {"id": "H2", "vulnerability_class": "Missing Security Header (HSTS)", "exploitability_status": "confirmed",
         "evidence": {"status_code": 404}},
        # 18) Security header on real HTML page -> CONFIRMED
        {"id": "H3", "vulnerability_class": "Missing Security Header (X-Frame-Options)", "exploitability_status": "confirmed",
         "affected_url": "https://t/account", "evidence": {"content_type": "text/html", "status_code": 200}},
    ]

    res = eliminate_false_positives(findings, tech_stack=["nginx"], scan_context={})

    print(f"CONFIRMED ({len(res['confirmed'])}):      {[f['id'] for f in res['confirmed']]}")
    print(f"CANDIDATES ({len(res['candidates'])}):     {[f['id'] for f in res['candidates']]}")
    print(f"FALSE_POSITIVES ({len(res['false_positives'])}): {[f['id'] for f in res['false_positives']]}")
    print(f"FP RATE: {res['fp_rate']}%")
    print(f"IMPROVEMENTS: {json.dumps(res['confidence_improvements'])}")
    print("\nSample FP reason (X1):",
          next(f['fp_reason'] for f in res['false_positives'] if f['id'] == 'X1'))
    print("Sample CANDIDATE reason (S3):",
          next(f['candidate_reasons'] for f in res['candidates'] if f['id'] == 'S3'))

    # --- assertions ---
    confirmed_ids = {f["id"] for f in res["confirmed"]}
    candidate_ids = {f["id"] for f in res["candidates"]}
    fp_ids = {f["id"] for f in res["false_positives"]}

    assert confirmed_ids == {"X2", "S4", "I3", "F3", "H3"}, f"confirmed mismatch: {confirmed_ids}"
    assert candidate_ids == {"S3", "F2"}, f"candidate mismatch: {candidate_ids}"
    assert fp_ids == {"X1", "X3", "S1", "S2", "I1", "I2", "F1", "R1", "R2", "H1", "H2"}, f"fp mismatch: {fp_ids}"
    # every output finding carries a valid exploitability_status
    for bucket, status in (("confirmed", CONFIRMED), ("candidates", CANDIDATE), ("false_positives", FALSE_POSITIVE)):
        for f in res[bucket]:
            assert f["exploitability_status"] == status
    # fp_rate sanity
    assert abs(res["fp_rate"] - round(100 * 11 / 18, 1)) < 0.01, res["fp_rate"]
    # all FPs have a reason
    assert all(f.get("fp_reason") for f in res["false_positives"])
    # accounting: 11 eliminated
    assert res["confidence_improvements"]["eliminated"] == 11
    # graceful on garbage
    assert eliminate_false_positives([], [], {})["fp_rate"] == 0.0
    assert eliminate_false_positives(None, None, None)["confirmed"] == []

    print("\n[ALL SELF-TESTS PASSED]")
