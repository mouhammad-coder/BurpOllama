"""
proxy_handler.py — Heuristic Pre-Filter for Burp Passive Layer
Runs BEFORE the Gemini queue to prevent backup under the 14 RPM free tier.
Only state-changing, parameter-bearing, or structured requests reach the LLM.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Optional

# ── Content-types that are NEVER worth AI analysis ───────────────────────────
DROP_CONTENT_TYPES = {
    # Images
    "image/png", "image/jpeg", "image/jpg", "image/gif",
    "image/webp", "image/svg+xml", "image/x-icon", "image/vnd.microsoft.icon",
    "image/avif", "image/tiff", "image/bmp",
    # Fonts
    "font/woff", "font/woff2", "font/ttf", "font/otf",
    "application/font-woff", "application/font-woff2",
    "application/x-font-ttf", "application/x-font-opentype",
    # Stylesheets
    "text/css",
    # Static/compiled JS bundles (not API responses)
    "application/javascript", "text/javascript",
    # Media
    "audio/mpeg", "audio/ogg", "video/mp4", "video/webm",
    # Archives
    "application/zip", "application/x-gzip",
    # PDF / binary
    "application/pdf", "application/octet-stream",
}

# ── URL patterns that signal telemetry / tracking — always drop ──────────────
DROP_URL_PATTERNS = re.compile(
    r"(?i)("
    r"google-analytics\.com|googletagmanager\.com|"
    r"segment\.com|mixpanel\.com|amplitude\.com|"
    r"hotjar\.com|fullstory\.com|heap\.io|"
    r"doubleclick\.net|adservice\.google|"
    r"facebook\.com/tr|connect\.facebook\.net|"
    r"bat\.bing\.com|analytics\.|telemetry\.|"
    r"beacon\.|tracking\.|pixel\.|metrics\."
    r")"
)

# ── Static asset file extensions in the path ─────────────────────────────────
DROP_EXTENSIONS = re.compile(
    r"(?i)\.(png|jpg|jpeg|gif|ico|svg|webp|avif|bmp|tiff|"
    r"woff2?|ttf|otf|eot|"
    r"css|map|"
    r"mp3|mp4|webm|ogg|flac|"
    r"zip|gz|tar|rar|pdf|"
    r"exe|dll|bin)(\?.*)?$"
)

# ── Methods that always indicate state change → always queue ─────────────────
STATE_CHANGE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# ── Query parameter names that signal interesting targets ────────────────────
INTERESTING_PARAM_RE = re.compile(
    r"(?i)^(id|uid|user_?id|account_?id|order_?id|doc_?id|"
    r"user|account|profile|admin|role|token|key|auth|"
    r"search|query|q|filter|sort|order|page|limit|offset|"
    r"file|path|url|redirect|next|return|callback|"
    r"action|cmd|exec|debug|preview|format|output|"
    r"template|view|type|category|item|product|"
    r"invoice|transaction|session|uuid|slug)$"
)

# ── Content-types that carry structured payloads → always queue ───────────────
STRUCTURED_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "text/xml",
    "application/graphql",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/ld+json",
    "application/vnd.api+json",
}


class HeuristicPreFilter:
    """
    Stateless pre-filter that decides whether a Burp-intercepted request
    is worth sending to Gemini for deep analysis.

    Decision tree (first matching rule wins):
      1. DROP  — telemetry/tracking URL
      2. DROP  — static asset extension in path
      3. DROP  — response Content-Type is binary/static
      4. QUEUE — state-changing HTTP method (POST/PUT/DELETE/PATCH)
      5. QUEUE — request Content-Type is structured (JSON/XML/form)
      6. QUEUE — URL has query params matching interesting param names
      7. QUEUE — URL has any query params AND is not a pure GET to a static path
      8. QUEUE — response Content-Type is application/json (API response)
      9. DROP  — everything else (pure GET, no params, boring CT)
    """

    def __init__(self):
        self._total_seen    = 0
        self._total_queued  = 0
        self._total_dropped = 0

    def should_queue(
        self,
        method:           str,
        url:              str,
        request_ct:       str = "",
        response_ct:      str = "",
        request_body:     str = "",
        response_status:  int = 200,
    ) -> tuple[bool, str]:
        """
        Returns (should_queue: bool, reason: str).
        Call this for every intercepted request before adding to Gemini queue.
        """
        self._total_seen += 1
        method  = (method  or "GET").upper()
        req_ct  = (request_ct  or "").lower().split(";")[0].strip()
        resp_ct = (response_ct or "").lower().split(";")[0].strip()

        parsed = urlparse(url)
        path   = parsed.path or "/"
        params = parse_qs(parsed.query)

        # ── Rule 1: Telemetry / tracking URL ─────────────────────────────────
        if DROP_URL_PATTERNS.search(url):
            return self._drop("telemetry/tracking URL")

        # ── Rule 2: Static asset extension ───────────────────────────────────
        if DROP_EXTENSIONS.search(path):
            return self._drop("static asset extension")

        # ── Rule 3: Binary / static response Content-Type ────────────────────
        if resp_ct in DROP_CONTENT_TYPES:
            return self._drop("binary/static response content-type: {}".format(resp_ct))

        # ── Rule 4: State-changing method ─────────────────────────────────────
        if method in STATE_CHANGE_METHODS:
            return self._queue("state-change method: {}".format(method))

        # ── Rule 5: Structured request body ──────────────────────────────────
        if req_ct in STRUCTURED_CONTENT_TYPES:
            return self._queue("structured request content-type: {}".format(req_ct))

        # ── Rule 6: Interesting query parameter names ─────────────────────────
        if params:
            for param_name in params.keys():
                if INTERESTING_PARAM_RE.match(param_name):
                    return self._queue("interesting param: ?{}=".format(param_name))

        # ── Rule 7: Any query params on a non-static path ────────────────────
        if params and not DROP_EXTENSIONS.search(path):
            return self._queue("parameterized GET request ({} params)".format(len(params)))

        # ── Rule 8: JSON API response ─────────────────────────────────────────
        if resp_ct == "application/json":
            return self._queue("JSON API response")

        # ── Rule 9: Large form body on GET (unusual — worth checking) ─────────
        if method == "GET" and request_body and len(request_body) > 50:
            return self._queue("GET with non-empty body ({} bytes)".format(len(request_body)))

        # ── Default: drop ────────────────────────────────────────────────────
        return self._drop("pure GET, no params, uninteresting content-type")

    def _queue(self, reason: str) -> tuple[bool, str]:
        self._total_queued += 1
        return True, reason

    def _drop(self, reason: str) -> tuple[bool, str]:
        self._total_dropped += 1
        return False, reason

    @property
    def stats(self) -> dict:
        ratio = (self._total_queued / self._total_seen * 100) if self._total_seen else 0
        return {
            "seen":    self._total_seen,
            "queued":  self._total_queued,
            "dropped": self._total_dropped,
            "queue_ratio_pct": round(ratio, 1),
        }

    def reset(self):
        self._total_seen    = 0
        self._total_queued  = 0
        self._total_dropped = 0


# ── Module-level singleton ────────────────────────────────────────────────────
pre_filter = HeuristicPreFilter()


def should_queue_for_gemini(
    method:          str,
    url:             str,
    request_ct:      str = "",
    response_ct:     str = "",
    request_body:    str = "",
    response_status: int = 200,
) -> bool:
    """
    Convenience wrapper around HeuristicPreFilter.should_queue().
    Returns bool only — use this in main.py /analyze route.
    """
    result, _ = pre_filter.should_queue(
        method, url, request_ct, response_ct, request_body, response_status
    )
    return result
