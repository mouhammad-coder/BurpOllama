"""
utils.py — HTTP Pruning & Pre-Processing Utilities v2
Cleans raw HTTP data before it reaches the LLM triage layer.
Spec: exact whitelist, Base64 >50 chars, SVG strip, contextual body slicing.
"""

import re
import json
from typing import Optional
from urllib.parse import urlparse

# ── Exact header whitelists (spec-compliant) ──────────────────────────────────

# Keep ONLY these request headers — everything else is noise
REQUEST_HEADER_WHITELIST = {
    "host",
    "authorization",
    "cookie",
    "origin",
    "content-type",
    "content-length",
    "referer",
    "x-requested-with",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "x-session-id",
    "x-user-id",
    "x-correlation-id",
    "if-none-match",
    "if-modified-since",
}

# Keep ONLY these response headers
RESPONSE_HEADER_WHITELIST = {
    "content-type",
    "content-security-policy",
    "set-cookie",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "permissions-policy",
    "www-authenticate",
    "server",
    "location",
    "x-powered-by",
    "cache-control",
    "pragma",
    "age",
    "vary",
    "etag",
    "x-cache",
    "cf-cache-status",
    "x-varnish",
    "surrogate-control",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
}

# ── Noise-stripping regexes ───────────────────────────────────────────────────

# Base64 strings longer than 50 chars (spec: >50)
_B64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){13,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)

# Data URIs with base64 payload
_DATA_URI_RE = re.compile(
    r'data:[a-z/+\-]+;base64,[A-Za-z0-9+/=]{20,}',
    re.IGNORECASE
)

# SVG <path> elements with d="..." data
_SVG_PATH_RE = re.compile(
    r'<path[^>]*\sd="[^"]{40,}"[^>]*/?>',
    re.IGNORECASE | re.DOTALL
)

# Inline SVG polyline/polygon points
_SVG_POINTS_RE = re.compile(
    r'(?:points|d)="[0-9\s,.\-]{60,}"',
    re.IGNORECASE
)

# Long hex blobs (nonces, fingerprints, hashes)
_HEX_BLOB_RE = re.compile(r'\b[0-9a-fA-F]{48,}\b')

# Webpack / minified JS bundle noise (function(){...} > 300 chars)
_WEBPACK_RE = re.compile(r'!function\([^)]{0,30}\)\{.{300,}\}', re.DOTALL)

# URL-encoded blobs
_URL_ENC_RE = re.compile(r'(?:%[0-9A-Fa-f]{2}){30,}')


def _strip_noise(text: str) -> str:
    """Remove heavy non-informative data from any text blob."""
    text = _DATA_URI_RE.sub('[DATA_URI_REMOVED]',    text)
    text = _SVG_PATH_RE.sub('[SVG_PATH_REMOVED]',    text)
    text = _SVG_POINTS_RE.sub('[SVG_POINTS_REMOVED]',text)
    text = _B64_RE.sub('[BASE64_BLOB_REMOVED]',      text)
    text = _HEX_BLOB_RE.sub('[HEX_BLOB]',            text)
    text = _URL_ENC_RE.sub('[URL_ENCODED_BLOB]',     text)
    text = _WEBPACK_RE.sub('[WEBPACK_BUNDLE_REMOVED]',text)
    return text


# ── Header pruners ────────────────────────────────────────────────────────────

def prune_request_headers(raw: str) -> str:
    """
    Keep only whitelisted request headers.
    Unknown custom headers (non-standard names) are retained since they
    may carry auth tokens or session identifiers.
    """
    kept = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            kept.append(line)   # first line (e.g. GET /path HTTP/1.1)
            continue
        name = line.split(":", 1)[0].lower().strip()
        # Keep whitelisted OR unknown custom headers (starts with x- not in drop list)
        is_standard_drop = (
            name in {
                "user-agent", "accept", "accept-encoding", "accept-language",
                "connection", "keep-alive", "upgrade-insecure-requests",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-user", "dnt", "te", "priority",
                "cache-control", "pragma",
            }
        )
        if name in REQUEST_HEADER_WHITELIST or not is_standard_drop:
            kept.append(line)
    return "\n".join(kept)


def prune_response_headers(raw: str) -> str:
    """Keep only whitelisted response headers."""
    kept = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            kept.append(line)   # status line
            continue
        name = line.split(":", 1)[0].lower().strip()
        if name in RESPONSE_HEADER_WHITELIST:
            kept.append(line)
    return "\n".join(kept)


# ── Body extractors ───────────────────────────────────────────────────────────

def extract_xss_context(body: str, payload: str, context_lines: int = 5) -> str:
    """
    text/html: find the reflection line, return ±context_lines with context label.
    Detects: SCRIPT_TAG_CONTEXT | EVENT_HANDLER_ATTRIBUTE | HTML_ATTRIBUTE |
             HTML_COMMENT | RAW_HTML_CONTEXT
    """
    if not payload or payload not in body:
        return _strip_noise(body[:800])

    lines = body.splitlines()
    idx   = next((i for i, l in enumerate(lines) if payload in l), None)
    if idx is None:
        return _strip_noise(body[:800])

    start   = max(0, idx - context_lines)
    end     = min(len(lines), idx + context_lines + 1)
    snippet = "\n".join(lines[start:end])

    # Detect injection context
    sl = snippet.lower()
    pl = re.escape(payload.lower())

    if re.search(r'<script[^>]*>.*' + pl, sl, re.DOTALL):
        ctx = "SCRIPT_TAG_CONTEXT"
    elif re.search(r'on\w+\s*=\s*["\'][^"\']*' + pl, sl):
        ctx = "EVENT_HANDLER_ATTRIBUTE"
    elif re.search(r'\w[\w-]*\s*=\s*["\'][^"\']*' + pl, sl):
        ctx = "HTML_ATTRIBUTE"
    elif re.search(r'<!--.*' + pl, sl, re.DOTALL):
        ctx = "HTML_COMMENT"
    else:
        ctx = "RAW_HTML_CONTEXT"

    return "[XSS_CONTEXT: {}]\n{}".format(ctx, _strip_noise(snippet))


def extract_sqli_context(body: str, error_pattern: str, window: int = 1000) -> str:
    """
    application/sql-error: 1000-char window centred on the detected error.
    """
    m = re.search(error_pattern, body, re.IGNORECASE)
    if not m:
        return _strip_noise(body[:window])
    start = max(0, m.start() - window // 2)
    end   = min(len(body), m.end()  + window // 2)
    return "[SQLI_ERROR_WINDOW]\n" + _strip_noise(body[start:end])


def extract_api_context(body: str, max_items: int = 2, max_total: int = 2000) -> str:
    """
    application/json: parse, slice arrays to max_items, re-minify.
    Falls back to plain truncation on parse failure.
    """
    try:
        data    = json.loads(body)
        trimmed = _truncate_json(data, max_items)
        result  = json.dumps(trimmed, separators=(",", ":"))
        return result[:max_total]
    except (json.JSONDecodeError, ValueError, RecursionError):
        return _strip_noise(body[:max_total])


def _truncate_json(obj, max_items: int):
    """Recursively truncate JSON arrays to max_items objects."""
    if isinstance(obj, list):
        sliced = [_truncate_json(i, max_items) for i in obj[:max_items]]
        if len(obj) > max_items:
            sliced.append({"__truncated__": "{} more items omitted".format(len(obj) - max_items)})
        return sliced
    elif isinstance(obj, dict):
        return {k: _truncate_json(v, max_items) for k, v in obj.items()}
    return obj


def _looks_like_json(text: str) -> bool:
    s = text.strip()
    return bool(s) and s[0] in ("{", "[")


# ── Master pruner ─────────────────────────────────────────────────────────────

def prune_http_for_llm(
    request_headers:  str,
    request_body:     str,
    response_headers: str,
    response_body:    str,
    finding_type:     str = "generic",
    payload:          str = "",
    error_pattern:    str = "",
    max_body:         int = 3000,
) -> dict:
    """
    Master function. Prune an HTTP exchange for efficient LLM consumption.

    finding_type: "xss" | "sqli" | "api" | "generic"

    Returns:
        pruned_request_headers, pruned_request_body,
        pruned_response_headers, pruned_response_body
    """
    # Prune headers
    req_h  = prune_request_headers(request_headers  or "")
    resp_h = prune_response_headers(response_headers or "")

    # Prune request body
    req_b  = _strip_noise(request_body or "")[:max_body]

    # Prune response body — content-type aware
    raw_resp = _strip_noise(response_body or "")
    ft       = finding_type.lower()

    # Infer from response headers if not explicitly specified
    resp_ct = ""
    for line in (response_headers or "").splitlines():
        if line.lower().startswith("content-type:"):
            resp_ct = line.split(":", 1)[1].lower().strip()
            break

    if ft == "xss" and payload:
        resp_b = extract_xss_context(raw_resp, payload)
    elif ft == "sqli" and error_pattern:
        resp_b = extract_sqli_context(raw_resp, error_pattern)
    elif ft == "api" or "application/json" in resp_ct or _looks_like_json(raw_resp):
        resp_b = extract_api_context(raw_resp)
    elif "text/html" in resp_ct and payload:
        resp_b = extract_xss_context(raw_resp, payload)
    else:
        resp_b = raw_resp[:max_body]

    return {
        "pruned_request_headers":  req_h,
        "pruned_request_body":     req_b,
        "pruned_response_headers": resp_h,
        "pruned_response_body":    resp_b,
    }


# ── Structural JSON comparator (IDOR) ─────────────────────────────────────────

SENSITIVE_KEYS = {
    "email", "phone", "mobile", "ssn", "tax_id", "dob", "birthday",
    "address", "street", "zipcode", "postal", "credit_card", "card_number",
    "account_number", "balance", "salary", "password", "passwd", "secret",
    "token", "api_key", "private_key", "uuid", "national_id",
    "passport", "driver_license", "ip_address", "location", "coordinates",
    "gender", "date_of_birth", "full_name", "first_name", "last_name",
}


def structural_json_diff(body_orig: str, body_mod: str) -> dict:
    """
    Compare two JSON responses for IDOR detection.
    Returns: keys_match, sensitive_keys_found, data_differs, is_idor_candidate, reason
    """
    result = {
        "keys_match":           False,
        "sensitive_keys_found": [],
        "data_differs":         False,
        "is_idor_candidate":    False,
        "reason":               "",
    }
    try:
        orig = json.loads(body_orig)
        mod  = json.loads(body_mod)
    except (json.JSONDecodeError, ValueError):
        diff = abs(len(body_orig) - len(body_mod))
        result["is_idor_candidate"] = 0 < diff < 500
        result["reason"] = "Non-JSON: size diff={}B".format(diff)
        return result

    orig_keys = set(_flatten_keys(orig))
    mod_keys  = set(_flatten_keys(mod))
    result["keys_match"] = (orig_keys == mod_keys)

    all_mod_lower  = {k.lower().split(".")[-1] for k in mod_keys}
    found_sensitive = [k for k in SENSITIVE_KEYS if k in all_mod_lower]
    result["sensitive_keys_found"] = found_sensitive

    if result["keys_match"] and orig != mod:
        result["data_differs"] = True

    if found_sensitive and result["data_differs"]:
        result["is_idor_candidate"] = True
        result["reason"] = "Sensitive keys {} differ across IDs".format(found_sensitive[:3])
    elif result["keys_match"] and result["data_differs"]:
        result["is_idor_candidate"] = True
        result["reason"] = "Same JSON structure, different values for different ID"

    return result


def _flatten_keys(obj, prefix: str = "") -> list:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = "{}.{}".format(prefix, k) if prefix else k
            keys.append(full)
            keys.extend(_flatten_keys(v, full))
    elif isinstance(obj, list) and obj:
        keys.extend(_flatten_keys(obj[0], "{}[0]".format(prefix)))
    return keys
