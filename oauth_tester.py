"""Active, evidence-driven OAuth security checks.

The tester is deliberately conservative: it only reports issues when the
target's response demonstrates acceptance, replay, or leakage. Merely exposing
an OAuth endpoint or supporting a standards-compliant optional parameter is not
reported as a vulnerability.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from scope_policy import scope_policy
from waf_engine import throttle
from request_safety import execute_guarded_request


OAUTH_HINTS = (
    "oauth", "authorize", "authorization", "token", "callback", "redirect_uri",
    "client_id", "response_type", "code_challenge", "openid", ".well-known",
)
TOKEN_PATH_HINTS = ("token", "access_token", "oauth/token", "connect/token")
REFERRER_SINK_HINTS = ("referer", "referrer", "log", "debug", "trace", "echo", "request")
SECRET_KEYS = {
    "access_token", "refresh_token", "id_token", "client_secret", "code",
    "authorization", "code_verifier",
}
ERROR_MARKERS = (
    "invalid_request", "invalid_redirect", "redirect_uri_mismatch",
    "invalid_grant", "invalid_code", "invalid_state", "state mismatch",
    "code_verifier", "pkce", "unsupported_response_type",
)


def _oauth_url(url: str) -> bool:
    parsed = urlparse(url)
    blob = "{}?{}".format(parsed.path, parsed.query).lower()
    return any(hint in blob for hint in OAUTH_HINTS)


def _redact_text(value: str, limit: int = 4000) -> str:
    text = str(value or "")
    for key in SECRET_KEYS:
        text = re.sub(
            r'(?i)("{}"\s*:\s*")([^"]*)'.format(re.escape(key)),
            lambda match: match.group(1) + "<redacted>",
            text,
        )
        text = re.sub(
            r"(?i)(\b{}=)([^&\s]+)".format(re.escape(key)),
            lambda match: match.group(1) + "<redacted>",
            text,
        )
    text = re.sub(
        r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+",
        r"\1<redacted>",
        text,
    )
    return text[:limit]


def _headers(headers: httpx.Headers | dict) -> dict[str, str]:
    result = {}
    for key, value in dict(headers or {}).items():
        result[str(key)] = (
            "<redacted>"
            if str(key).lower() in {"authorization", "cookie", "set-cookie"}
            else _redact_text(str(value), 1000)
        )
    return result


def _request_response(response: httpx.Response) -> dict[str, Any]:
    request = response.request
    request_body = request.content.decode("utf-8", errors="replace") if request.content else ""
    return {
        "request": {
            "method": request.method,
            "url": _redact_text(str(request.url), 4000),
            "headers": _headers(request.headers),
            "body": _redact_text(request_body),
        },
        "response": {
            "status_code": response.status_code,
            "headers": _headers(response.headers),
            "body": _redact_text(response.text),
        },
    }


def _curl(method: str, url: str, *, headers: dict | None = None, data: dict | None = None) -> str:
    parts = ["curl", "-i", "-X", method.upper()]
    for key, value in (headers or {}).items():
        if key.lower() not in {"authorization", "cookie"}:
            parts.extend(["-H", "{}: {}".format(key, value)])
    if data is not None:
        parts.extend(["--data", urlencode(data)])
    parts.append(url)
    # posix=True produces a portable command suitable for reports.
    return " ".join(shlex.quote(str(part)) for part in parts)


def _finding(
    title: str,
    url: str,
    cwe: str,
    severity: str,
    evidence_pairs: list[dict[str, Any]],
    curl_command: str,
    exploitation_scenario: str,
    remediation: str,
    *,
    confidence: int = 95,
    method: str = "GET",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "request_response_pairs": evidence_pairs,
        "curl_poc": curl_command,
    }
    result = {
        "id": "OAUTH-{}-{}".format(
            int(time.time() * 1000),
            abs(hash(title + url + json.dumps(evidence, sort_keys=True))) % 99999,
        ),
        "source": "oauth-tester",
        "title": title,
        "vuln_type": title,
        "vulnerability_class": "OAuth Security",
        "severity": severity,
        "confidence": confidence,
        "url": url,
        "affected_url": url,
        "method": method,
        "description": exploitation_scenario,
        "technical_impact": exploitation_scenario,
        "business_impact": exploitation_scenario,
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "request_response_pair": evidence_pairs,
        "curl_command": curl_command,
        "poc": curl_command,
        "exploitation_scenario": exploitation_scenario,
        "remediation": remediation,
        "cwe": cwe,
        "cvss": 8.1 if severity == "HIGH" else 6.5,
        "exploitability_status": "confirmed",
        "evidence_strength": "strong",
        "false_positive_risk": "low",
        "redaction_status": "redacted",
        "reproduction_steps": [
            "Send the provided curl request within the authorized test scope.",
            "Compare the response with the captured request/response evidence.",
            "Confirm the demonstrated OAuth security property is still bypassed.",
        ],
        "safe_manual_validation_steps": [
            "Use only approved OAuth clients and disposable test accounts.",
            "Do not retain or disclose authorization codes or tokens.",
            "Stop if the flow would authorize access to another user's account.",
        ],
    }
    if extra:
        result.update(extra)
    return result


async def _request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    if throttle.host_dead:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        response = await execute_guarded_request(
            client,
            scope_policy,
            method,
            url,
            action="active",
            follow_redirects=False,
            timeout=httpx.Timeout(12.0),
            **kwargs,
        )
        if response is not None:
            if throttle.is_block_response(
                response.status_code,
                response.text[:16000],
                dict(response.headers),
                url,
            ):
                await throttle.record_block(
                    response.status_code,
                    response.text[:200],
                    url,
                    dict(response.headers),
                )
            return response
        return None


def _query_url(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _flat_params(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlparse(url).query).items() if values}


def _location(response: httpx.Response | None, request_url: str) -> str:
    if not response:
        return ""
    location = response.headers.get("location", "")
    return urljoin(request_url, location) if location else ""


def _successful_oauth_response(response: httpx.Response | None, request_url: str) -> bool:
    if not response:
        return False
    blob = "{} {}".format(response.text[:2000], response.headers.get("location", "")).lower()
    if any(marker in blob for marker in ERROR_MARKERS):
        return False
    location = _location(response, request_url)
    location_params = parse_qs(urlparse(location).query)
    fragment_params = parse_qs(urlparse(location).fragment)
    return bool(
        response.status_code in (200, 201, 202, 302, 303, 307, 308)
        and (
            {"code", "access_token", "id_token"} & set(location_params)
            or {"access_token", "id_token"} & set(fragment_params)
            or "consent" in blob
            or "approve" in blob
        )
    )


def _redirect_escaped(response: httpx.Response | None, request_url: str) -> bool:
    location = _location(response, request_url)
    if not location:
        return False
    parsed = urlparse(location)
    return (
        parsed.scheme.lower() == "javascript"
        or (parsed.hostname or "").lower() == "evil.com"
        or (parsed.hostname or "").lower().endswith(".evil.com")
    )


def _token_payload(response: httpx.Response | None) -> bool:
    if not response or response.status_code not in (200, 201):
        return False
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    return bool(
        isinstance(payload, dict)
        and any(payload.get(key) for key in ("access_token", "id_token", "refresh_token"))
    )


def _token_endpoints(base_url: str, urls: list[str]) -> list[str]:
    endpoints = [
        url for url in urls
        if any(hint in urlparse(url).path.lower() for hint in TOKEN_PATH_HINTS)
    ]
    root = "{}://{}".format(urlparse(base_url).scheme, urlparse(base_url).netloc)
    endpoints.extend(
        urljoin(root, path)
        for path in ("/oauth/token", "/token", "/connect/token")
    )
    return list(dict.fromkeys(endpoints))


def _open_redirect_candidates(urls: list[str]) -> list[str]:
    result = []
    for url in urls:
        params = _flat_params(url)
        for key in ("redirect", "next", "url", "return", "returnurl", "goto", "target", "to"):
            if key in params:
                modified = dict(params)
                modified[key] = "https://evil.com"
                result.append(_query_url(url, modified))
                break
    return result[:10]


async def _test_state(
    oauth_urls: list[str],
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    findings = []
    for url in oauth_urls:
        params = _flat_params(url)
        if "state" not in params:
            continue

        missing = dict(params)
        missing.pop("state", None)
        missing_url = _query_url(url, missing)
        response = await _request(client, "GET", missing_url)
        if _successful_oauth_response(response, missing_url):
            findings.append(_finding(
                "OAuth State Parameter Not Enforced",
                url,
                "CWE-352",
                "HIGH",
                [_request_response(response)],
                _curl("GET", missing_url),
                "An attacker can initiate or substitute an OAuth authorization response without a bound state value, enabling login CSRF or account-linking CSRF.",
                "Generate a cryptographically random state per authorization attempt, bind it to the initiating browser session, and reject missing, mismatched, expired, or reused values.",
                extra={"oauth_test": "state_missing"},
            ))

        # A discovered callback containing both code and state can be safely
        # replayed to determine whether the client consumes state/code once.
        if "code" in params:
            first = await _request(client, "GET", url)
            second = await _request(client, "GET", url)
            if (
                _successful_oauth_response(first, url)
                and _successful_oauth_response(second, url)
                and first is not None
                and second is not None
            ):
                findings.append(_finding(
                    "OAuth State or Callback Replay Accepted",
                    url,
                    "CWE-352",
                    "HIGH",
                    [_request_response(first), _request_response(second)],
                    _curl("GET", url),
                    "An attacker who obtains a valid OAuth callback URL can replay it, potentially forcing a victim into the attacker's session or repeating an account-linking action.",
                    "Consume state and authorization codes atomically on first use and reject every replay.",
                    extra={"oauth_test": "state_reuse"},
                ))
    return findings


async def _test_redirect_uris(
    oauth_urls: list[str],
    discovered_urls: list[str],
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    findings = []
    chains = _open_redirect_candidates(discovered_urls)
    for url in oauth_urls:
        params = _flat_params(url)
        original = params.get("redirect_uri")
        if not original:
            continue

        parsed_redirect = urlparse(original)
        host = parsed_redirect.hostname or "trusted.example"
        path = parsed_redirect.path or "/callback"
        payloads = [
            ("userinfo-host-confusion", "{}://{}@evil.com{}".format(
                parsed_redirect.scheme or "https", host, path
            )),
            ("redirect-query", original + ("&" if "?" in original else "?") + "redirect=https://evil.com"),
            ("javascript-uri", "javascript:alert(1)"),
        ]
        payloads.extend(("open-redirect-chain", chain) for chain in chains)

        for test_name, payload in payloads:
            modified = dict(params)
            modified["redirect_uri"] = payload
            test_url = _query_url(url, modified)
            response = await _request(client, "GET", test_url)
            evidence_pairs = [_request_response(response)] if response else []
            escaped = _redirect_escaped(response, test_url)
            if not escaped and test_name == "open-redirect-chain":
                first_hop = _location(response, test_url)
                if first_hop:
                    chain_response = await _request(client, "GET", first_hop)
                    if chain_response:
                        evidence_pairs.append(_request_response(chain_response))
                    escaped = _redirect_escaped(chain_response, first_hop)
            if not escaped:
                continue
            findings.append(_finding(
                "OAuth Redirect URI Validation Bypass",
                url,
                "CWE-601",
                "HIGH",
                evidence_pairs,
                _curl("GET", test_url),
                "An attacker can supply a crafted redirect_uri and receive an OAuth redirect at an attacker-controlled destination, allowing authorization-code or token theft.",
                "Match redirect URIs exactly against pre-registered absolute HTTPS URIs. Reject userinfo, JavaScript schemes, nested redirects, wildcards, and open-redirect intermediaries.",
                extra={
                    "oauth_test": "redirect_uri_validation",
                    "redirect_payload_type": test_name,
                    "redirect_payload": payload,
                },
            ))
            break
    return findings


async def _test_code_and_pkce(
    base_url: str,
    oauth_urls: list[str],
    discovered_urls: list[str],
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    findings = []
    token_urls = _token_endpoints(base_url, discovered_urls)
    authorization_params = [_flat_params(url) for url in oauth_urls]
    pkce_expected = any(
        params.get("code_challenge") or params.get("code_challenge_method")
        for params in authorization_params
    )
    for url in oauth_urls:
        params = _flat_params(url)
        code = params.get("code")
        if not code:
            continue
        correlated = next(
            (
                candidate for candidate in authorization_params
                if (
                    not params.get("client_id")
                    or candidate.get("client_id") == params.get("client_id")
                )
                and (
                    candidate.get("redirect_uri")
                    or candidate.get("code_challenge")
                )
            ),
            {},
        )
        form = {
            "grant_type": "authorization_code",
            "code": code,
        }
        for key in ("client_id", "client_secret", "redirect_uri"):
            value = params.get(key) or correlated.get(key)
            if value:
                form[key] = value

        for token_url in token_urls:
            first = await _request(
                client,
                "POST",
                token_url,
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if not _token_payload(first):
                continue

            if pkce_expected:
                findings.append(_finding(
                    "OAuth PKCE Bypass",
                    token_url,
                    "CWE-287",
                    "HIGH",
                    [_request_response(first)],
                    _curl(
                        "POST",
                        token_url,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data=form,
                    ),
                    "An intercepted authorization code can be exchanged without the code_verifier, defeating PKCE and allowing account takeover.",
                    "Require a valid code_verifier for every code issued with a code_challenge and bind the verifier, client, redirect URI, and code atomically.",
                    method="POST",
                    extra={"oauth_test": "pkce_bypass"},
                ))

            second = await _request(
                client,
                "POST",
                token_url,
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if _token_payload(second):
                findings.append(_finding(
                    "OAuth Authorization Code Reuse",
                    token_url,
                    "CWE-287",
                    "HIGH",
                    [_request_response(first), _request_response(second)],
                    _curl(
                        "POST",
                        token_url,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data=form,
                    ),
                    "A stolen authorization code can be replayed more than once to mint additional token sets.",
                    "Make authorization codes single-use, short-lived, and atomically invalidated during the first successful exchange.",
                    method="POST",
                    extra={"oauth_test": "authorization_code_reuse"},
                ))
            break
    return findings


async def _test_referrer_leakage(
    discovered_urls: list[str],
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    findings = []
    token_urls = []
    sinks = []
    for url in discovered_urls:
        parsed = urlparse(url)
        params = _flat_params(url)
        fragment = parse_qs(parsed.fragment)
        if any(key in params or key in fragment for key in ("access_token", "id_token")):
            token_urls.append(url)
        if any(hint in parsed.path.lower() for hint in REFERRER_SINK_HINTS):
            sinks.append(url)

    for token_url in token_urls[:5]:
        token_query = urlparse(token_url).query
        if not token_query:
            continue  # URL fragments are never transmitted in Referer headers.
        for sink in sinks[:5]:
            response = await _request(
                client,
                "GET",
                sink,
                headers={"Referer": token_url},
            )
            if not response:
                continue
            body = response.text
            sensitive_values = [
                value
                for key, values in parse_qs(token_query).items()
                if key in {"access_token", "id_token"}
                for value in values
            ]
            if sensitive_values and any(value and value in body for value in sensitive_values):
                findings.append(_finding(
                    "OAuth Token Leakage Through Referer Logging",
                    sink,
                    "CWE-598",
                    "HIGH",
                    [_request_response(response)],
                    _curl("GET", sink, headers={"Referer": token_url}),
                    "OAuth tokens placed in a URL query are forwarded in the Referer header and exposed by a logging or diagnostic endpoint, allowing token theft by log readers or downstream services.",
                    "Never place tokens in URL queries. Set Referrer-Policy: no-referrer, redact sensitive logs, and use authorization-code flow with PKCE.",
                    extra={"oauth_test": "referer_token_leakage"},
                ))
                break
    return findings


def _test_implicit_fragments(discovered_urls: list[str]) -> list[dict[str, Any]]:
    findings = []
    for url in discovered_urls:
        fragment = parse_qs(urlparse(url).fragment)
        if not any(fragment.get(key) for key in ("access_token", "id_token")):
            continue
        synthetic = {
            "request": {
                "method": "BROWSER_NAVIGATION",
                "url": _redact_text(url),
                "headers": {},
                "body": "",
            },
            "response": {
                "status_code": 0,
                "headers": {},
                "body": "OAuth token observed in the discovered URL fragment.",
            },
        }
        findings.append(_finding(
            "OAuth Implicit Flow Token in URL Fragment",
            url,
            "CWE-598",
            "MEDIUM",
            [synthetic],
            _curl("GET", url.split("#", 1)[0]),
            "A browser-delivered access token is exposed to front-end code and browser history/session tooling, increasing the impact of XSS, malicious extensions, and client-side telemetry leakage.",
            "Disable implicit flow and use authorization-code flow with PKCE. Keep access and refresh tokens out of URLs.",
            confidence=98,
            extra={"oauth_test": "implicit_fragment_leakage"},
        ))
    return findings


async def test_oauth_flow(
    base_url: str,
    discovered_urls: list,
    client: httpx.AsyncClient,
) -> list[dict]:
    """Test discovered OAuth surfaces and return only confirmed findings."""
    urls = [
        str(url)
        for url in dict.fromkeys([base_url, *(discovered_urls or [])])
        if isinstance(url, str) and url.startswith(("http://", "https://"))
    ]
    oauth_urls = [url for url in urls if _oauth_url(url)]
    if not oauth_urls:
        return []

    findings: list[dict[str, Any]] = []
    findings.extend(await _test_state(oauth_urls, client))
    findings.extend(await _test_redirect_uris(oauth_urls, urls, client))
    findings.extend(await _test_code_and_pkce(base_url, oauth_urls, urls, client))
    findings.extend(await _test_referrer_leakage(urls, client))
    findings.extend(_test_implicit_fragments(urls))

    deduped = []
    seen = set()
    for finding in findings:
        key = (finding["vuln_type"], finding["url"], finding.get("oauth_test", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped
