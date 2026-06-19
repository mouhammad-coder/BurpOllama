"""Extract runtime API endpoints from downloaded JavaScript bundles."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from scope_policy import scope_policy


CALL_PATTERNS = (
    re.compile(
        r"""(?is)\bfetch\s*\(\s*(?P<expr>`[^`]*`|'[^']*'|"[^"]*")"""
    ),
    re.compile(
        r"""(?is)\baxios\.(?:get|post|put)\s*\(\s*
        (?P<expr>`[^`]*`|'[^']*'|"[^"]*")""",
        re.VERBOSE,
    ),
    re.compile(
        r"""(?is)\bthis\.(?:\$http|http)\.(?:get|post|put)\s*\(\s*
        (?P<expr>`[^`]*`|'[^']*'|"[^"]*")""",
        re.VERBOSE,
    ),
)

BASE_CONCAT_RE = re.compile(
    r"""(?is)\b(?:apiUrl|API_BASE)\b\s*\+\s*
    (?P<expr>(?:`[^`]*`|'[^']*'|"[^"]*")
    (?:\s*\+\s*(?:[A-Za-z_$][\w$.[\]]*|`[^`]*`|'[^']*'|"[^"]*"))*)""",
    re.VERBOSE,
)

STRING_CONCAT_RE = re.compile(
    r"""(?is)(?P<expr>
    (?:`/[^`]*`|'/(?:\\.|[^'])*'|"/(?:\\.|[^"])*")
    (?:\s*\+\s*(?:[A-Za-z_$][\w$.[\]]*|`[^`]*`|'[^']*'|"[^"]*"))+
    )""",
    re.VERBOSE,
)

TEMPLATE_PATH_RE = re.compile(r"""(?s)`(?P<path>/[^`\r\n]*)`""")
VERSION_PATH_RE = re.compile(
    r"""(?P<quote>["'])(?P<path>/(?:api/)?v[12]/[^"'`\s\\]*)(?P=quote)""",
    re.IGNORECASE,
)
STRING_TOKEN_RE = re.compile(
    r"""`(?P<template>[^`]*)`|'(?P<single>(?:\\.|[^'])*)'|"(?P<double>(?:\\.|[^"])*)"
    |(?P<identifier>[A-Za-z_$][\w$.[\]]*)""",
    re.VERBOSE | re.DOTALL,
)
TEMPLATE_VARIABLE_RE = re.compile(r"\$\{[^}]+\}")


def _javascript_string(value: str) -> str:
    return (
        value.replace(r"\/", "/")
        .replace(r"\\", "\\")
        .replace(r"\'", "'")
        .replace(r"\"", '"')
    )


def _expression_path(expression: str, *, prepend_root: bool = False) -> str:
    """Convert a literal/template/concatenation expression into a path."""
    parts = []
    for match in STRING_TOKEN_RE.finditer(expression or ""):
        literal = (
            match.group("template")
            if match.group("template") is not None
            else match.group("single")
            if match.group("single") is not None
            else match.group("double")
        )
        if literal is not None:
            parts.append(_javascript_string(literal))
        elif match.group("identifier"):
            parts.append("{var}")
    path = "".join(parts)
    path = TEMPLATE_VARIABLE_RE.sub("{var}", path)
    path = re.sub(r"\{var\}(?:\{var\})+", "{var}", path)
    if prepend_root and path and not path.startswith("/"):
        path = "/" + path
    return path


def _base_origin(base_url: str) -> str:
    parsed = urlparse(str(base_url or ""))
    if not parsed.scheme:
        parsed = urlparse("https://" + str(base_url or "").lstrip("/"))
    return "{}://{}".format(parsed.scheme or "https", parsed.netloc)


def _normalize_candidate(candidate: str, base_url: str) -> str:
    value = str(candidate or "").strip()
    if not value:
        return ""
    value = TEMPLATE_VARIABLE_RE.sub("{var}", value)
    value = value.split("#", 1)[0]
    origin = _base_origin(base_url)
    origin_host = (urlparse(origin).hostname or "").lower()

    if value.startswith("//"):
        value = "{}:{}".format(urlparse(origin).scheme, value)
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if (parsed.hostname or "").lower() != origin_host:
            return ""
        full_url = value
    elif value.startswith("/"):
        full_url = urljoin(origin + "/", value.lstrip("/"))
    else:
        return ""

    parsed = urlparse(full_url)
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        re.sub(r"/{2,}", "/", parsed.path),
        "",
        parsed.query,
        "",
    ))
    return normalized if scope_policy.validate_target(normalized, action="scan")[0] else ""


def _extract_from_source(source: str, base_url: str) -> set[str]:
    candidates: set[str] = set()

    for pattern in CALL_PATTERNS:
        for match in pattern.finditer(source):
            candidates.add(_expression_path(match.group("expr")))

    for match in BASE_CONCAT_RE.finditer(source):
        candidates.add(_expression_path(match.group("expr"), prepend_root=True))

    for match in STRING_CONCAT_RE.finditer(source):
        candidates.add(_expression_path(match.group("expr")))

    for match in TEMPLATE_PATH_RE.finditer(source):
        candidates.add(TEMPLATE_VARIABLE_RE.sub("{var}", match.group("path")))

    for match in VERSION_PATH_RE.finditer(source):
        candidates.add(match.group("path"))

    return {
        normalized
        for candidate in candidates
        if (normalized := _normalize_candidate(candidate, base_url))
    }


async def extract_js_endpoints(
    js_urls: list[str],
    base_url: str,
    client: httpx.AsyncClient,
) -> list[str]:
    """Download non-minified JavaScript files and return discovered full URLs."""
    endpoints: set[str] = set()
    seen_js: set[str] = set()

    for js_url in js_urls or []:
        js_url = str(js_url or "")
        path = urlparse(js_url).path.lower()
        if not path.endswith(".js") or path.endswith(".min.js") or js_url in seen_js:
            continue
        seen_js.add(js_url)

        allowed, _reason = scope_policy.record_request(js_url, action="scan")
        if not allowed:
            continue
        try:
            response = await client.get(js_url)
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue

        endpoints.update(_extract_from_source(response.text, base_url))

    return sorted(endpoints)
