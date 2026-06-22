"""Conservative WAF differential-testing workflow.

This module does not generate obfuscated exploit payloads.  It compares safe
read-only request variants to identify proxy/origin inconsistencies that merit
manual review.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx


SAFE_HEADER_VARIANTS = (
    {"Accept": "application/json"},
    {"Accept": "text/html"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"Cache-Control": "no-cache"},
)


def _path_variants(url: str) -> list[str]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    candidates = {path}
    if path != "/":
        candidates.add(path.rstrip("/") + "/")
    candidates.add("//" + path.lstrip("/"))
    return [urlunsplit((parsed.scheme, parsed.netloc, item, parsed.query, "")) for item in candidates]


async def analyze_waf_differentials(
    url: str,
    *,
    authorized: bool,
    intensive_authorized: bool,
    timeout: float = 8.0,
) -> dict:
    if not authorized or not intensive_authorized:
        return {
            "ran": False,
            "reason": "WAF differential testing requires explicit authorization and intensive-testing consent.",
            "observations": [],
        }
    observations = []
    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=timeout,
        headers={"User-Agent": "BurpOllama/3.2 authorized-security-test"},
    ) as client:
        for candidate in _path_variants(url):
            for headers in ({}, *SAFE_HEADER_VARIANTS):
                try:
                    response = await client.get(candidate, headers=headers)
                    observations.append({
                        "url": candidate,
                        "headers": headers,
                        "status": response.status_code,
                        "length": len(response.content),
                        "server": response.headers.get("server", ""),
                    })
                except httpx.HTTPError as exc:
                    observations.append({"url": candidate, "headers": headers, "error": str(exc)})
    signatures = {
        (item.get("status"), item.get("length"))
        for item in observations if "status" in item
    }
    return {
        "ran": True,
        "possible_inconsistency": len(signatures) > 2,
        "observations": observations,
        "note": "Differences are candidates only and require manual validation.",
    }

