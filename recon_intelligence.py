"""recon_intelligence.py

Advanced recon intelligence for authorized bug bounty programs.

    async def advanced_recon_intelligence(
        target, discovered_urls, js_contents, live_hosts, tech_stack
    ) -> dict

This function performs NO network requests. It mines data you have ALREADY
collected (URLs, JavaScript/HTML bodies, live hosts, fingerprinted tech) to
surface hidden attack surface that other hunters miss: inferred API endpoints,
technology-specific sensitive paths, fuzzable parameters, the authentication
surface, and a bounty-potential score per endpoint.

Returns a dict with:
    hidden_endpoints, high_value_targets, api_schema_hints, parameter_wordlist,
    auth_surface, tech_specific_paths, recommendations

Everything is wrapped in defensive error handling; a malformed input in one
analysis stage never aborts the others.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse


# ===========================================================================
# REGEX LIBRARY (compiled once)
# ===========================================================================
# fetch("..."), fetch(`...`), fetch('...')
_RE_FETCH = re.compile(r"""fetch\s*\(\s*[`'"]([^`'"]+)[`'"]""", re.I)
# axios.get('...'), axios.post(`...`), axios({url:'...'})
_RE_AXIOS = re.compile(r"""axios\s*(?:\.\s*(get|post|put|patch|delete|head|options))?\s*\(\s*[`'"]([^`'"]+)[`'"]""", re.I)
# axios({ url: '...', method: 'post' })  /  $.ajax({url:'...'})
_RE_URL_PROP = re.compile(r"""\burl\s*:\s*[`'"]([^`'"]+)[`'"]""", re.I)
_RE_METHOD_PROP = re.compile(r"""\bmethod\s*:\s*[`'"](get|post|put|patch|delete|head|options)[`'"]""", re.I)
# XMLHttpRequest .open('GET', '...')
_RE_XHR = re.compile(r"""\.open\s*\(\s*[`'"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]""", re.I)
# Generic string constants that look like API paths: "/api/v1/users", "/v2/orders"
_RE_API_PATH = re.compile(r"""[`'"](\/(?:api|rest|graphql|v\d+|internal|service|services|gateway)[A-Za-z0-9_\-\/\.\{\}:]*)[`'"]""")
# Any rooted path constant (broader; used for parameter + resource mining)
_RE_ANY_PATH = re.compile(r"""[`'"](\/[A-Za-z0-9_\-\/\.\{\}:]{2,}?)[`'"]""")
# process.env.API_URL / import.meta.env.VITE_API / window.__ENV__.API_BASE
_RE_ENV = re.compile(r"""(?:process\.env|import\.meta\.env|window\.__ENV__?)\.([A-Z0-9_]+)""")
# baseURL / API_URL constant assignments
_RE_BASEURL = re.compile(r"""(?:baseURL|baseUrl|API_URL|API_BASE|apiBase|API_ENDPOINT|endpoint)\s*[:=]\s*[`'"]([^`'"]+)[`'"]""", re.I)
# Absolute http(s) URLs embedded in JS
_RE_ABS_URL = re.compile(r"""[`'"](https?:\/\/[^`'"\s]+)[`'"]""")
# GraphQL operations
_RE_GQL_OP = re.compile(r"""\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?\s*[\({]""")
_RE_GQL_TAG = re.compile(r"""\bgql\s*`([^`]+)`""", re.S)
_RE_GQL_FIELD = re.compile(r"""[`'"]?\b(query|mutation)\b\s*[:=]""", re.I)
# HTML form fields
_RE_INPUT_NAME = re.compile(r"""<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*[`'"]([^`'"]+)[`'"]""", re.I)
_RE_FORM_ACTION = re.compile(r"""<form\b[^>]*\baction\s*=\s*[`'"]([^`'"]+)[`'"]""", re.I)
# Anchor / link hrefs (navigational attack surface, e.g. oauth callbacks)
_RE_HREF = re.compile(r"""\bhref\s*=\s*[`'"]([^`'"]+)[`'"]""", re.I)
# JSON keys: "key":
_RE_JSON_KEY = re.compile(r"""[`'"]([A-Za-z_][A-Za-z0-9_]{1,40})[`'"]\s*:""")
# JS variable / param-ish identifiers in query building: params.set('x'), {userId, token}
_RE_PARAMS_SET = re.compile(r"""(?:searchParams|params|qs)\.(?:set|append|get)\s*\(\s*[`'"]([A-Za-z0-9_\-\[\]]+)[`'"]""")
_RE_TEMPLATE_QS = re.compile(r"""[?&]([A-Za-z0-9_\-\[\]]+)=""")


# ===========================================================================
# TECHNOLOGY-SPECIFIC SENSITIVE PATHS
# ===========================================================================
TECH_PATHS: Dict[str, List[str]] = {
    "wordpress": [
        "/xmlrpc.php", "/wp-cron.php", "/wp-json/wp/v2/users", "/wp-json/",
        "/wp-login.php", "/wp-admin/", "/wp-config.php.bak", "/?author=1",
    ],
    "laravel": [
        "/telescope", "/telescope/requests", "/horizon", "/horizon/api/stats",
        "/_debugbar/open", "/.env", "/storage/logs/laravel.log",
    ],
    "spring": [  # Spring Boot
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
        "/actuator/mappings", "/actuator/configprops", "/actuator/threaddump",
        "/h2-console", "/actuator/gateway/routes",
    ],
    "django": [
        "/admin/", "/django-admin/", "/api/schema/", "/api/schema/swagger-ui/",
        "/static/admin/", "/__debug__/",
    ],
    "nextjs": [
        "/_next/static/", "/api/auth/session", "/api/auth/providers",
        "/api/auth/csrf", "/__nextjs_original-stack-frame", "/_next/data/",
    ],
    "express": [
        "/graphql", "/playground", "/api-docs", "/api-docs.json",
        "/swagger.json", "/.env", "/status",
    ],
    "rails": [
        "/rails/info", "/rails/info/routes", "/admin", "/sidekiq",
        "/rails/mailers", "/assets/manifest.json",
    ],
    "flask": ["/console", "/api/swagger.json", "/static/", "/admin"],
    "fastapi": ["/docs", "/redoc", "/openapi.json"],
    "graphql": ["/graphql", "/graphiql", "/playground", "/v1/graphql", "/api/graphql"],
    "nginx": ["/nginx_status", "/.well-known/", "/server-status"],
    "apache": ["/server-status", "/server-info", "/.htaccess", "/.htpasswd"],
    "jenkins": ["/script", "/asynchPeople/", "/api/json", "/cli"],
    "grafana": ["/api/datasources", "/api/health", "/login"],
    "kubernetes": ["/api/v1/namespaces", "/metrics", "/healthz", "/version"],
    "drupal": ["/CHANGELOG.txt", "/user/login", "/admin", "/jsonapi"],
    "tomcat": ["/manager/html", "/host-manager/html", "/examples/"],
}

# Aliases so varied fingerprints map to a canonical tech key.
_TECH_ALIASES: Dict[str, str] = {
    "wp": "wordpress", "word press": "wordpress",
    "spring boot": "spring", "springboot": "spring", "java spring": "spring",
    "next": "nextjs", "next.js": "nextjs", "nextjs": "nextjs",
    "express.js": "express", "expressjs": "express", "node express": "express",
    "ruby on rails": "rails", "ror": "rails",
    "django rest": "django", "drf": "django",
    "fast api": "fastapi",
    "apache httpd": "apache", "httpd": "apache",
    "k8s": "kubernetes",
}


def _canonical_tech(name: str) -> Optional[str]:
    n = str(name).strip().lower()
    if not n:
        return None
    if n in TECH_PATHS:
        return n
    if n in _TECH_ALIASES:
        return _TECH_ALIASES[n]
    # substring match (e.g. "WordPress 6.2" -> wordpress)
    for key in TECH_PATHS:
        if key in n:
            return key
    for alias, key in _TECH_ALIASES.items():
        if alias in n:
            return key
    return None


# ===========================================================================
# SCORING KEYWORDS  (category -> (weight, keyword fragments))
# ===========================================================================
_SCORE_RULES: List[Tuple[str, int, Tuple[str, ...]]] = [
    ("admin", 35, ("/admin", "administrator", "superuser", "backoffice", "/manage", "/internal", "/console", "/staff", "root")),
    ("debug_exposure", 30, ("actuator", "heapdump", "telescope", "horizon", "debugbar", "phpinfo", "/.env", "/.git", "swagger", "openapi", "api-docs", "/config", "h2-console", "/server-status")),
    ("payment", 30, ("payment", "/pay", "billing", "invoice", "charge", "checkout", "/card", "subscription", "refund", "wallet", "balance", "payout", "transaction")),
    ("auth", 22, ("login", "signin", "signup", "register", "oauth", "token", "session", "password", "reset", "forgot", "2fa", "mfa", "otp", "/sso", "saml", "jwt", "logout", "verify")),
    ("user_data", 20, ("/user", "/users", "/account", "profile", "customer", "/me", "email", "phone", "address", "ssn", "export", "/pii", "personal")),
    ("file_ops", 16, ("upload", "/file", "import", "/export", "attachment", "document", "/media", "avatar", "/download", "backup")),
    ("privileged_action", 14, ("delete", "/update", "create", "grant", "/role", "permission", "approve", "impersonate", "promote", "disable", "reset")),
    ("api_core", 10, ("/graphql", "/api", "/v1", "/v2", "/v3", "/rest", "/internal", "/gateway", "/service")),
]


# ===========================================================================
# AUTH SURFACE CLASSIFICATION
# ===========================================================================
_AUTH_TYPES: List[Tuple[str, Tuple[str, ...]]] = [
    ("oauth_callback", ("oauth", "/callback", "auth/callback", "redirect_uri", "/sso", "saml/acs")),
    ("login", ("login", "signin", "/auth/login", "authenticate", "session/new")),
    ("signup", ("signup", "register", "registration", "/join", "create-account")),
    ("password_reset", ("password", "reset", "forgot", "recover", "change-password")),
    ("mfa_2fa", ("2fa", "mfa", "otp", "totp", "verify-code", "two-factor", "authenticator")),
    ("token_refresh", ("refresh", "refresh-token", "token/refresh", "/renew", "rotate-token")),
    ("session", ("session", "logout", "/auth/me", "whoami", "current-user", "/auth/session")),
    ("token_issue", ("/token", "oauth/token", "/jwt", "access_token", "grant")),
]


# ===========================================================================
# UTILITIES
# ===========================================================================
def _norm_url(u: str) -> str:
    """Strip fragments and trailing slashes (except root) for de-duplication."""
    try:
        p = urlparse(u)
        path = p.path or "/"
        if len(path) > 1:
            path = path.rstrip("/")
        rebuilt = f"{p.scheme}://{p.netloc}{path}" if p.scheme and p.netloc else path
        if p.query:
            rebuilt += f"?{p.query}"
        return rebuilt
    except Exception:
        return u


def _bases(target: str, live_hosts: Sequence[str]) -> List[str]:
    """Return absolute origin bases (https://host) from target + live hosts."""
    bases: List[str] = []
    for h in [target, *(live_hosts or [])]:
        if not h:
            continue
        h = str(h).strip()
        if "://" not in h:
            h = "https://" + h
        p = urlparse(h)
        if p.scheme and p.netloc:
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in bases:
                bases.append(origin)
    return bases


def _is_pathlike(s: str) -> bool:
    return isinstance(s, str) and s.startswith("/") and " " not in s and len(s) > 1


# ===========================================================================
# 1. API ENDPOINT INFERENCE FROM JAVASCRIPT
# ===========================================================================
def _infer_from_js(js_contents: Dict[str, str]) -> Dict[str, Any]:
    """Extract API paths, base URLs, env refs, methods, and GraphQL ops from JS/HTML."""
    out: Dict[str, Any] = {
        "path_fragments": set(),     # rooted paths like /api/v1/users
        "absolute_urls": set(),      # http(s)://...
        "base_urls": set(),          # baseURL constants
        "env_refs": set(),           # process.env.X names
        "methods": {},               # path -> set(methods)
        "graphql_ops": set(),        # "query GetUser", "mutation Login"
        "graphql_present": False,
    }
    if not isinstance(js_contents, dict):
        return out

    for url, content in js_contents.items():
        if not isinstance(content, str) or not content:
            continue
        try:
            # fetch()
            for m in _RE_FETCH.findall(content):
                _record_path(m, out)
            # axios.<method>('...')
            for method, path in _RE_AXIOS.findall(content):
                _record_path(path, out, method or None)
            # { url: '...', method: '...' }
            url_props = _RE_URL_PROP.findall(content)
            method_props = _RE_METHOD_PROP.findall(content)
            mdefault = method_props[0] if method_props else None
            for p in url_props:
                _record_path(p, out, mdefault)
            # XHR .open('GET','...')
            for method, path in _RE_XHR.findall(content):
                _record_path(path, out, method)
            # generic API-looking constants
            for p in _RE_API_PATH.findall(content):
                _record_path(p, out)
            # base URLs
            for b in _RE_BASEURL.findall(content):
                if b:
                    out["base_urls"].add(b.rstrip("/"))
                    if b.startswith("http"):
                        out["absolute_urls"].add(b.rstrip("/"))
            # absolute URLs
            for a in _RE_ABS_URL.findall(content):
                out["absolute_urls"].add(a)
            # env refs
            for e in _RE_ENV.findall(content):
                out["env_refs"].add(e)
            # GraphQL
            if "/graphql" in content.lower() or _RE_GQL_TAG.search(content) or _RE_GQL_FIELD.search(content):
                out["graphql_present"] = True
            for kind, name in _RE_GQL_OP.findall(content):
                if name:
                    out["graphql_ops"].add(f"{kind} {name}")
            for block in _RE_GQL_TAG.findall(content):
                for kind, name in _RE_GQL_OP.findall(block):
                    if name:
                        out["graphql_ops"].add(f"{kind} {name}")
                        out["graphql_present"] = True
            # Navigational links: anchor hrefs and form actions (HTML bodies).
            for href in _RE_HREF.findall(content):
                h = href.strip()
                if h.startswith(("http://", "https://")) or h.startswith("/"):
                    _record_path(h, out)
            for action in _RE_FORM_ACTION.findall(content):
                a = action.strip()
                if a.startswith(("http://", "https://")) or a.startswith("/"):
                    _record_path(a, out)
        except Exception:
            # One bad blob must not kill the whole inference pass.
            continue
    return out


def _record_path(raw: str, out: Dict[str, Any], method: Optional[str] = None) -> None:
    """Normalise a discovered URL/path into the inference accumulator."""
    if not raw or not isinstance(raw, str):
        return
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        out["absolute_urls"].add(raw)
        path = urlparse(raw).path or "/"
    elif raw.startswith("/"):
        path = raw
        out["path_fragments"].add(_strip_qs(raw))
    else:
        return  # relative fragments without a base are too ambiguous
    if method:
        key = _strip_qs(path)
        out["methods"].setdefault(key, set()).add(method.upper())


def _strip_qs(p: str) -> str:
    return p.split("?")[0].split("#")[0]


# ===========================================================================
# 2 & build hidden endpoints from inference + tech paths
# ===========================================================================
def _build_tech_paths(tech_stack: Sequence[str], bases: Sequence[str]) -> Dict[str, List[str]]:
    """Map each detected technology to absolute URLs worth probing."""
    result: Dict[str, List[str]] = {}
    detected: Set[str] = set()
    for t in tech_stack or []:
        canon = _canonical_tech(t)
        if canon:
            detected.add(canon)
    for tech in sorted(detected):
        urls: List[str] = []
        for base in bases or [""]:
            for path in TECH_PATHS.get(tech, []):
                urls.append(urljoin(base + "/", path.lstrip("/")) if base else path)
        # de-dup preserving order
        seen, deduped = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u); deduped.append(u)
        if deduped:
            result[tech] = deduped
    return result


# ===========================================================================
# 3. PARAMETER DISCOVERY
# ===========================================================================
def _discover_parameters(discovered_urls: Sequence[str], js_contents: Dict[str, str]) -> List[str]:
    """Collect candidate parameter names from URLs, forms, JSON, and JS."""
    params: Set[str] = set()

    # Query params from URLs.
    for u in discovered_urls or []:
        try:
            for k, _ in parse_qsl(urlparse(str(u)).query, keep_blank_values=True):
                if k:
                    params.add(k)
        except Exception:
            continue

    if isinstance(js_contents, dict):
        for content in js_contents.values():
            if not isinstance(content, str) or not content:
                continue
            try:
                params.update(_RE_INPUT_NAME.findall(content))      # HTML form fields
                params.update(_RE_JSON_KEY.findall(content))         # JSON keys
                params.update(_RE_PARAMS_SET.findall(content))       # params.set('x')
                params.update(_RE_TEMPLATE_QS.findall(content))      # ?x=..&y=..
            except Exception:
                continue

    # Clean noise: drop very long / clearly non-param tokens.
    cleaned = {
        p.strip() for p in params
        if p and len(p) <= 40 and re.fullmatch(r"[A-Za-z0-9_\-\[\]\.]+", p or "")
    }
    # Drop obvious non-parameters (common JS keywords / mime types).
    noise = {"function", "return", "true", "false", "null", "undefined", "var", "let", "const",
             "type", "application", "text", "json", "charset", "utf-8"}
    cleaned = {p for p in cleaned if p.lower() not in noise}
    return sorted(cleaned)


# ===========================================================================
# 4. AUTH SURFACE DETECTION
# ===========================================================================
def _classify_auth(urls: Sequence[str]) -> List[Dict[str, str]]:
    """Classify URLs into authentication surface categories."""
    surface: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for u in urls:
        low = str(u).lower()
        for auth_type, kws in _AUTH_TYPES:
            if any(k in low for k in kws):
                key = (auth_type, _norm_url(u))
                if key not in seen:
                    seen.add(key)
                    surface.append({"type": auth_type, "url": u})
                break  # first (most specific) match wins
    return surface


# ===========================================================================
# 5. HIGH-VALUE ENDPOINT SCORING
# ===========================================================================
def _score_endpoint(url: str) -> Tuple[int, List[str]]:
    """Score an endpoint 0-100 by bounty potential; return (score, reasons)."""
    low = str(url).lower()
    score = 0
    reasons: List[str] = []
    for category, weight, kws in _SCORE_RULES:
        if any(k in low for k in kws):
            score += weight
            reasons.append(category)
    # Bonus: write-ish methods implied by path verbs already counted; add small
    # bump for parameterised / templated object ids (IDOR-friendly).
    if re.search(r"/\{?\b(id|user_?id|account_?id|uuid)\}?(/|$)", low) or re.search(r"/:\w*id", low):
        score += 8
        reasons.append("object_id_in_path")
    # Deep API nesting is generally more interesting than static assets.
    if low.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".map", ".ico")):
        score = max(0, score - 30)
        reasons.append("static_asset_penalty")
    return min(score, 100), sorted(set(reasons))


# ===========================================================================
# RECOMMENDATION ENGINE
# ===========================================================================
def _build_recommendations(
    tech_paths: Dict[str, List[str]],
    inference: Dict[str, Any],
    auth_surface: List[Dict[str, str]],
    high_value: List[Dict[str, Any]],
) -> List[str]:
    recs: List[str] = []

    # Tech-specific high-signal probes.
    tk = set(tech_paths.keys())
    if "spring" in tk:
        recs.append("Spring Boot detected: probe /actuator/env, /actuator/heapdump, and "
                    "/actuator/mappings for leaked secrets and internal routes (often unauthenticated).")
    if "wordpress" in tk:
        recs.append("WordPress detected: enumerate users via /wp-json/wp/v2/users and /?author=1; "
                    "test xmlrpc.php for pingback SSRF and credential brute force amplification.")
    if "laravel" in tk:
        recs.append("Laravel detected: check /telescope and /horizon for exposed request/debug data, "
                    "and attempt to retrieve /.env.")
    if "django" in tk:
        recs.append("Django detected: check /api/schema/ (DRF) for the full API contract and test the "
                    "admin login at /admin/ for default/weak credentials.")
    if "nextjs" in tk:
        recs.append("Next.js detected: inspect /api/auth/session and /_next/data/ for SSR data leakage "
                    "and review /api/* routes enumerated from JS.")
    if "rails" in tk:
        recs.append("Rails detected: check /rails/info/routes (dev leak) and an exposed /sidekiq dashboard.")
    if "tomcat" in tk:
        recs.append("Tomcat detected: test /manager/html with default credentials (tomcat/tomcat) for WAR deploy RCE.")
    if "jenkins" in tk:
        recs.append("Jenkins detected: test /script (Groovy console) and /cli for unauthenticated RCE.")

    # GraphQL.
    if inference.get("graphql_present"):
        recs.append("GraphQL endpoint present: run introspection (or test if it's disabled), then map "
                    "queries/mutations" + (f" (seen: {', '.join(sorted(inference['graphql_ops'])[:5])})"
                                            if inference.get("graphql_ops") else "") +
                    " and pair with IDOR/authorization testing on object-id arguments.")

    # Env-driven base URLs / staging.
    if inference.get("env_refs"):
        recs.append("Client references environment variables (" +
                    ", ".join(sorted(inference["env_refs"])[:6]) +
                    "): look for leaked staging/internal API base URLs and test them for weaker auth.")
    if inference.get("base_urls"):
        recs.append("Hardcoded API base URL(s) found in JS (" +
                    ", ".join(sorted(inference["base_urls"])[:4]) +
                    "): confirm whether these alternate origins enforce the same authN/Z as production.")

    # Auth surface.
    auth_types = {a["type"] for a in auth_surface}
    if "oauth_callback" in auth_types:
        recs.append("OAuth callback endpoint(s) found: test redirect_uri validation for open-redirect / "
                    "token-leak chains.")
    if "password_reset" in auth_types:
        recs.append("Password-reset endpoint(s) found: test for host-header poisoning, token leakage in "
                    "Referer, and account-takeover via reset-token reuse.")
    if "token_refresh" in auth_types:
        recs.append("Token-refresh endpoint(s) found: test refresh-token rotation, revocation on logout, "
                    "and reuse-after-logout.")
    if "mfa_2fa" in auth_types:
        recs.append("2FA/MFA endpoint(s) found: test for OTP brute force (missing rate limit) and 2FA "
                    "bypass via response/flow manipulation.")

    # Top targets nudge.
    if high_value:
        top = high_value[0]
        recs.append(f"Highest-value target is {top['url']} (score {top['score']}, "
                    f"{', '.join(top['categories'][:3])}): prioritise authorization + IDOR testing here.")

    if not recs:
        recs.append("No high-signal tech/auth markers inferred; broaden recon (more JS bodies, "
                    "authenticated crawl) and fuzz the discovered parameter wordlist against API routes.")
    return recs


# ===========================================================================
# PUBLIC ENTRY POINT
# ===========================================================================
async def advanced_recon_intelligence(
    target: str,
    discovered_urls: List[str],
    js_contents: Dict[str, str],
    live_hosts: List[str],
    tech_stack: List[str],
) -> Dict[str, Any]:
    """Analyse already-collected recon data to surface hidden attack surface.

    Args:
        target: primary target host or URL (e.g. "example.com" or "https://example.com").
        discovered_urls: URLs already found during crawling.
        js_contents: mapping of {source_url: javascript_or_html_text}.
        live_hosts: hosts confirmed reachable (used to build absolute candidates).
        tech_stack: fingerprinted technologies (e.g. ["WordPress 6.2", "nginx"]).

    Returns:
        dict with keys: hidden_endpoints, high_value_targets, api_schema_hints,
        parameter_wordlist, auth_surface, tech_specific_paths, recommendations.

    Never raises: each analysis stage is independently guarded; on catastrophic
    failure a fully-formed empty structure is returned.
    """
    # Fully-formed default so callers always get every key.
    result: Dict[str, Any] = {
        "hidden_endpoints": [],
        "high_value_targets": [],
        "api_schema_hints": {},
        "parameter_wordlist": [],
        "auth_surface": [],
        "tech_specific_paths": {},
        "recommendations": [],
    }

    try:
        discovered_urls = [str(u) for u in (discovered_urls or []) if u]
        js_contents = js_contents if isinstance(js_contents, dict) else {}
        live_hosts = [str(h) for h in (live_hosts or []) if h]
        tech_stack = [str(t) for t in (tech_stack or []) if t]
        bases = _bases(target, live_hosts)

        known_norm: Set[str] = {_norm_url(u) for u in discovered_urls}

        # --- 1. JS inference ---------------------------------------------
        try:
            inference = _infer_from_js(js_contents)
        except Exception:
            inference = _infer_from_js({})

        # --- 2. Tech-specific paths --------------------------------------
        try:
            tech_paths = _build_tech_paths(tech_stack, bases)
        except Exception:
            tech_paths = {}
        result["tech_specific_paths"] = tech_paths

        # --- Build hidden endpoints (inferred + tech), excluding known ----
        hidden: List[str] = []
        hidden_seen: Set[str] = set()

        def _add_hidden(u: str) -> None:
            nu = _norm_url(u)
            if not nu or nu in known_norm or nu in hidden_seen:
                return
            hidden_seen.add(nu)
            hidden.append(u)

        # Absolute URLs found directly in JS.
        for a in sorted(inference["absolute_urls"]):
            _add_hidden(a)
        # Path fragments resolved against each base (and the bare path).
        for frag in sorted(inference["path_fragments"]):
            if bases:
                for base in bases:
                    _add_hidden(urljoin(base + "/", frag.lstrip("/")))
            else:
                _add_hidden(frag)
        # Tech-specific paths.
        for urls in tech_paths.values():
            for u in urls:
                _add_hidden(u)

        result["hidden_endpoints"] = hidden

        # --- 3. Parameter wordlist ---------------------------------------
        try:
            result["parameter_wordlist"] = _discover_parameters(discovered_urls, js_contents)
        except Exception:
            result["parameter_wordlist"] = []

        # --- 4. Auth surface (over known + hidden) -----------------------
        all_urls = discovered_urls + hidden
        try:
            result["auth_surface"] = _classify_auth(all_urls)
        except Exception:
            result["auth_surface"] = []

        # --- 5. High-value scoring (known + hidden) ----------------------
        scored: List[Dict[str, Any]] = []
        scored_seen: Set[str] = set()
        for u in all_urls:
            nu = _norm_url(u)
            if nu in scored_seen:
                continue
            scored_seen.add(nu)
            try:
                score, reasons = _score_endpoint(u)
            except Exception:
                score, reasons = 0, []
            if score <= 0:
                continue
            scored.append({
                "url": u,
                "score": score,
                "categories": reasons,
                "is_hidden": nu in hidden_seen,
            })
        scored.sort(key=lambda d: d["score"], reverse=True)
        result["high_value_targets"] = scored[:20]

        # --- API schema hints --------------------------------------------
        try:
            result["api_schema_hints"] = _build_schema_hints(inference, all_urls)
        except Exception:
            result["api_schema_hints"] = {}

        # --- Recommendations ---------------------------------------------
        try:
            result["recommendations"] = _build_recommendations(
                tech_paths, inference, result["auth_surface"], result["high_value_targets"]
            )
        except Exception:
            result["recommendations"] = []

    except Exception as exc:  # absolute backstop
        result["recommendations"] = [f"Recon analysis encountered an error and returned partial results: {exc}"]

    return result


def _build_schema_hints(inference: Dict[str, Any], all_urls: Sequence[str]) -> Dict[str, Any]:
    """Infer a coarse API structure: versions, resource groups, methods, GraphQL."""
    versions: Set[str] = set()
    resources: Dict[str, Set[str]] = {}
    methods: Dict[str, List[str]] = {}

    # Collect all paths (from inference fragments + known URLs).
    paths: Set[str] = set(inference.get("path_fragments", set()))
    for u in all_urls:
        try:
            p = urlparse(str(u)).path
            if p and p.startswith("/"):
                paths.add(_strip_qs(p))
        except Exception:
            continue

    for p in paths:
        segs = [s for s in p.split("/") if s]
        for s in segs:
            if re.fullmatch(r"v\d+", s, re.I):
                versions.add(s.lower())
        # Resource group = first non-version, non-"api" segment.
        meaningful = [s for s in segs if s.lower() not in {"api", "rest"} and not re.fullmatch(r"v\d+", s, re.I)]
        if meaningful:
            group = meaningful[0]
            resources.setdefault(group, set()).add(p)

    for path, ms in inference.get("methods", {}).items():
        methods[path] = sorted(ms)

    return {
        "detected_base_urls": sorted(inference.get("base_urls", set())),
        "absolute_api_origins": sorted({urlparse(a).scheme + "://" + urlparse(a).netloc
                                        for a in inference.get("absolute_urls", set())
                                        if urlparse(a).netloc}),
        "api_versions": sorted(versions),
        "resource_groups": {k: sorted(v) for k, v in sorted(resources.items(),
                                                            key=lambda kv: len(kv[1]), reverse=True)[:25]},
        "methods_by_path": methods,
        "env_variable_refs": sorted(inference.get("env_refs", set())),
        "graphql": {
            "present": inference.get("graphql_present", False),
            "operations": sorted(inference.get("graphql_ops", set())),
        },
    }


# ===========================================================================
# SELF-TEST
# ===========================================================================
if __name__ == "__main__":
    import asyncio
    import json

    js = {
        "https://example.com/app.js": """
            const API_URL = "https://api.example.com/v2";
            const base = process.env.NEXT_PUBLIC_API_BASE;
            async function load() {
              const r = await fetch("/api/v2/users/{id}/profile");
              await fetch(`/api/v2/payments/charge`, {method:'POST'});
              axios.get("/api/v2/orders");
              axios.post("/api/v2/auth/login", creds);
              const xhr = new XMLHttpRequest();
              xhr.open("DELETE", "/api/v2/admin/users/42");
              const q = gql`query GetMe { me { id email role } }`;
              fetch("/graphql", {method:'POST', body: q});
              params.set("redirect_uri", cb);
            }
        """,
        "https://example.com/login.html": """
            <form action="/auth/login" method="post">
              <input name="username"><input name="password" type="password">
              <input name="csrf_token" type="hidden">
            </form>
            <a href="/auth/oauth/callback?provider=google">Google</a>
            <a href="/auth/forgot-password">Reset</a>
            {"user_id": 1, "email": "x", "is_admin": false}
        """,
    }
    discovered = [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/search?q=test&page=2",
        "https://example.com/api/v2/orders",   # already known
    ]
    hosts = ["example.com", "api.example.com"]
    tech = ["WordPress 6.2", "nginx", "Spring Boot 2.7", "Next.js"]

    async def _main():
        res = await advanced_recon_intelligence("https://example.com", discovered, js, hosts, tech)

        print("=== HIDDEN ENDPOINTS (sample) ===")
        for u in res["hidden_endpoints"][:12]:
            print("  ", u)
        print(f"  ... {len(res['hidden_endpoints'])} total\n")

        print("=== TOP HIGH-VALUE TARGETS ===")
        for t in res["high_value_targets"][:8]:
            print(f"  {t['score']:3}  {t['url']}  {t['categories']}")

        print("\n=== AUTH SURFACE ===")
        for a in res["auth_surface"]:
            print(f"  {a['type']:16} {a['url']}")

        print("\n=== PARAMETER WORDLIST ===")
        print("  ", res["parameter_wordlist"])

        print("\n=== TECH-SPECIFIC PATHS (keys) ===")
        for tech_name, paths in res["tech_specific_paths"].items():
            print(f"  {tech_name}: {len(paths)} paths e.g. {paths[:2]}")

        print("\n=== API SCHEMA HINTS ===")
        print(json.dumps(res["api_schema_hints"], indent=2)[:900])

        print("\n=== RECOMMENDATIONS ===")
        for r in res["recommendations"]:
            print("  -", r)

        # --- assertions ---
        assert set(res.keys()) == {
            "hidden_endpoints", "high_value_targets", "api_schema_hints",
            "parameter_wordlist", "auth_surface", "tech_specific_paths", "recommendations"
        }, "missing/extra top-level keys"
        # known url excluded from hidden
        assert all("/api/v2/orders" not in u or "example.com/api/v2/orders" != _norm_url(u)
                   for u in res["hidden_endpoints"]), "known url leaked into hidden"
        # tech paths present for detected stacks
        assert "spring" in res["tech_specific_paths"], "spring paths missing"
        assert "wordpress" in res["tech_specific_paths"], "wordpress paths missing"
        # graphql detected
        assert res["api_schema_hints"]["graphql"]["present"], "graphql not detected"
        assert any("GetMe" in op for op in res["api_schema_hints"]["graphql"]["operations"]), "gql op missing"
        # versions + env refs
        assert "v2" in res["api_schema_hints"]["api_versions"], "version not inferred"
        assert "NEXT_PUBLIC_API_BASE" in res["api_schema_hints"]["env_variable_refs"], "env ref missing"
        # params discovered
        for must in ("username", "password", "csrf_token", "q", "page", "redirect_uri", "email"):
            assert must in res["parameter_wordlist"], f"param {must} missing"
        # auth surface classified
        atypes = {a["type"] for a in res["auth_surface"]}
        assert "login" in atypes and "oauth_callback" in atypes and "password_reset" in atypes, "auth types missing"
        # high value: admin/payment endpoints should outrank static
        top_urls = " ".join(t["url"] for t in res["high_value_targets"][:5]).lower()
        assert "admin" in top_urls or "payment" in top_urls or "charge" in top_urls, "high-value ranking off"
        # graceful on garbage input
        empty = await advanced_recon_intelligence("", None, None, None, None)
        assert set(empty.keys()) == set(res.keys()) and empty["hidden_endpoints"] == []

        print("\n[ALL SELF-TESTS PASSED]")

    asyncio.run(_main())
