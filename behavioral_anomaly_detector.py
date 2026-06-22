"""Bounded behavioral anomaly probes for discovered HTTP endpoints."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from request_safety import execute_guarded_request

from finding_model import normalize_finding


TIMEOUT = httpx.Timeout(12.0)
HTML_TAG_RE = re.compile(r"<[A-Za-z][^>]*>")


def _json_key_count(value: Any) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_json_key_count(nested) for nested in value.values())
    if isinstance(value, list):
        return sum(_json_key_count(nested) for nested in value[:20])
    return 0


def _response_metrics(response: httpx.Response, elapsed: float) -> dict[str, Any]:
    body = response.content or b""
    text = response.text or ""
    content_type = response.headers.get("content-type", "").lower()
    json_keys = 0
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            json_keys = _json_key_count(response.json())
        except ValueError:
            json_keys = 0
    html_tags = len(HTML_TAG_RE.findall(text)) if (
        "html" in content_type or "<html" in text[:1000].lower()
    ) else 0
    return {
        "status_code": response.status_code,
        "response_size": len(body),
        "response_time_ms": round(elapsed * 1000, 2),
        "json_keys": json_keys,
        "html_tags": html_tags,
        "content_type": content_type.split(";", 1)[0],
        "response_excerpt": text[:500],
    }


def _average_metrics(samples: list[dict]) -> dict[str, Any]:
    return {
        "status_code": samples[0]["status_code"],
        "response_size": int(round(sum(item["response_size"] for item in samples) / len(samples))),
        "response_time_ms": round(
            sum(item["response_time_ms"] for item in samples) / len(samples), 2
        ),
        "json_keys": int(round(sum(item["json_keys"] for item in samples) / len(samples))),
        "html_tags": int(round(sum(item["html_tags"] for item in samples) / len(samples))),
        "content_type": samples[0]["content_type"],
        "sample_count": len(samples),
        "response_excerpt": samples[0]["response_excerpt"],
    }


def _baseline_consistent(samples: list[dict]) -> bool:
    if len(samples) != 5 or len({item["status_code"] for item in samples}) != 1:
        return False
    sizes = [item["response_size"] for item in samples]
    average = sum(sizes) / len(sizes)
    if max(sizes) - min(sizes) > max(50, average * 0.15):
        return False
    structures = {
        (item["content_type"], item["json_keys"], item["html_tags"])
        for item in samples
    }
    return len(structures) == 1


def _structure(metrics: dict) -> tuple:
    return (
        metrics.get("content_type", ""),
        int(metrics.get("json_keys", 0) or 0),
        int(metrics.get("html_tags", 0) or 0),
    )


def _dramatic_change(baseline: dict, anomaly: dict) -> bool:
    baseline_size = max(1, int(baseline.get("response_size", 0) or 0))
    size_ratio = abs(int(anomaly.get("response_size", 0)) - baseline_size) / baseline_size
    return bool(
        anomaly.get("status_code") != baseline.get("status_code")
        or _structure(anomaly) != _structure(baseline)
        or size_ratio > 0.50
    )


async def _request(
    client: httpx.AsyncClient,
    policy,
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    content: bytes | str | None = None,
) -> tuple[httpx.Response | None, dict | None]:
    started = time.monotonic()
    response = await execute_guarded_request(
        client,
        policy,
        method,
        url,
        action="active",
        headers=headers,
        content=content,
        follow_redirects=False,
        timeout=TIMEOUT,
    )
    if response is None:
        return None, None
    return response, _response_metrics(response, time.monotonic() - started)


def _exact_request(method: str, url: str, headers: dict | None = None, body: str = "") -> str:
    parsed = urlparse(url)
    target = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    lines = [
        "{} {} HTTP/1.1".format(method.upper(), target),
        "Host: {}".format(parsed.netloc),
    ]
    lines.extend("{}: {}".format(key, value) for key, value in (headers or {}).items())
    if body:
        lines.extend(["Content-Length: {}".format(len(body.encode())), "", body])
    else:
        lines.append("")
    return "\r\n".join(lines)


async def _http10_request(url: str, policy) -> tuple[dict | None, str]:
    allowed, _reason = policy.record_request(url, action="active")
    if not allowed:
        return None, ""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    request_text = "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n".format(
        target, parsed.netloc
    )
    ssl_context = ssl._create_unverified_context() if parsed.scheme == "https" else None
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                parsed.hostname,
                port,
                ssl=ssl_context,
                server_hostname=parsed.hostname if ssl_context else None,
            ),
            timeout=10,
        )
        writer.write(request_text.encode("ascii", errors="ignore"))
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(2_000_000), timeout=12)
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None, request_text

    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    status_match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", header_text)
    status = int(status_match.group(1)) if status_match else 0
    content_type_match = re.search(r"(?im)^Content-Type:\s*([^\r\n;]+)", header_text)
    content_type = content_type_match.group(1).strip().lower() if content_type_match else ""
    text = body.decode("utf-8", errors="replace")
    json_keys = 0
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            json_keys = _json_key_count(json.loads(text))
        except ValueError:
            pass
    return {
        "status_code": status,
        "response_size": len(body),
        "response_time_ms": round((time.monotonic() - started) * 1000, 2),
        "json_keys": json_keys,
        "html_tags": len(HTML_TAG_RE.findall(text)) if (
            "html" in content_type or "<html" in text[:1000].lower()
        ) else 0,
        "content_type": content_type,
        "response_excerpt": text[:500],
    }, request_text


def _finding(
    anomaly_type: str,
    url: str,
    exact_request: str,
    baseline: dict,
    anomaly: dict,
    manual_test_description: str,
) -> dict:
    comparison = {
        "baseline": baseline,
        "anomaly": anomaly,
    }
    return normalize_finding({
        "source": "behavioral-anomaly-detector",
        "title": anomaly_type.replace("_", " ").title(),
        "vuln_type": anomaly_type,
        "vulnerability_class": anomaly_type,
        "severity": "MEDIUM",
        "confidence": 68,
        "url": url,
        "affected_url": url,
        "method": "MANUAL",
        "description": manual_test_description,
        "manual_test_description": manual_test_description,
        "evidence": json.dumps({
            "exact_request": exact_request,
            "comparison": comparison,
        }, ensure_ascii=False),
        "exact_request": exact_request,
        "baseline_anomaly_comparison": comparison,
        "exploitability_status": "needs_manual_validation",
        "evidence_strength": "weak",
        "false_positive_risk": "high",
        "business_impact": (
            "A confirmed behavioral difference could expose hidden data, debug output, "
            "alternate API versions, or an access-control bypass."
        ),
        "technical_impact": manual_test_description,
        "remediation": (
            "Normalize routing, content negotiation, encoding, version handling, and "
            "debug behavior at the edge and application layer. Reject unsupported variants."
        ),
        "cwe": "CWE-200",
        "reproduction_steps": [
            "Send the recorded baseline request several times and confirm stable behavior.",
            "Send the exact anomaly-triggering request captured in the finding.",
            "Compare status, response size, content type, JSON keys, and HTML tag count.",
            "Verify whether the difference exposes data or bypasses an intended control.",
        ],
        "safe_manual_validation_steps": [
            "Use only read-only requests or disposable authorized test data.",
            "Do not rely on a single response; confirm the difference remains stable.",
            "Stop if a request triggers an irreversible action.",
        ],
        "redaction_status": "redacted",
    })


async def detect_anomalies(
    url: str,
    client: httpx.AsyncClient,
    scope_policy,
) -> list[dict]:
    """Detect stable behavioral differences without claiming exploitability."""
    policy = scope_policy
    if not policy.config.active_testing_enabled or policy.config.passive_only_mode:
        return []
    if not policy.validate_target(url, action="active")[0]:
        return []

    baseline_samples = []
    for _ in range(5):
        _response, metrics = await _request(client, policy, "GET", url)
        if not metrics:
            return []
        baseline_samples.append(metrics)
    if not _baseline_consistent(baseline_samples):
        return []
    baseline = _average_metrics(baseline_samples)
    findings = []

    # A. Method swap
    for method in ("HEAD", "OPTIONS", "POST"):
        _response, metrics = await _request(
            client, policy, method, url, content=b"" if method == "POST" else None
        )
        if not metrics:
            continue
        if method == "POST" and (
            metrics["response_size"] > baseline["response_size"] + 50
            and metrics["response_size"] > baseline["response_size"] * 1.20
        ):
            findings.append(_finding(
                "method_swap_information_disclosure",
                url,
                _exact_request("POST", url, body=""),
                baseline,
                metrics,
                "POST with an empty body returned materially more data than the stable GET baseline. Test whether method routing exposes a hidden handler or additional fields.",
            ))
            break

    # B. Accept header manipulation
    accept_values = []
    if "html" in baseline["content_type"] or baseline["html_tags"] > 0:
        accept_values.append("application/json")
    if "json" in baseline["content_type"] or baseline["json_keys"] > 0:
        accept_values.append("application/xml")
    for accept in accept_values:
        headers = {"Accept": accept}
        _response, metrics = await _request(client, policy, "GET", url, headers=headers)
        if metrics and _dramatic_change(baseline, metrics):
            findings.append(_finding(
                "content_negotiation_disclosure",
                url,
                _exact_request("GET", url, headers),
                baseline,
                metrics,
                "Changing the Accept header materially changed the response format or structure. Test whether an alternate representation exposes additional or less-protected data.",
            ))
            break

    # C. Version header injection
    for header, value in (
        ("X-API-Version", "0"),
        ("X-API-Version", "99"),
        ("API-Version", "1.0-beta"),
    ):
        headers = {header: value}
        _response, metrics = await _request(client, policy, "GET", url, headers=headers)
        if metrics and _dramatic_change(baseline, metrics):
            findings.append(_finding(
                "version_endpoint_discovered",
                url,
                _exact_request("GET", url, headers),
                baseline,
                metrics,
                "An API version header selected behavior that differs from the stable baseline. Verify whether an undocumented or legacy version exposes weaker validation or authorization.",
            ))
            break

    # D. Debug header injection
    for header, value in (
        ("X-Debug", "true"),
        ("X-Dev-Mode", "1"),
        ("Debug", "1"),
        ("X-Test", "true"),
    ):
        headers = {header: value}
        _response, metrics = await _request(client, policy, "GET", url, headers=headers)
        if metrics and metrics["response_size"] > baseline["response_size"] * 1.20:
            findings.append(_finding(
                "debug_mode_disclosure",
                url,
                _exact_request("GET", url, headers),
                baseline,
                metrics,
                "A debug/development header increased the response size by more than 20%. Inspect the additional content for stack traces, configuration, internal paths, or sensitive fields.",
            ))
            break

    # E. Encoding variation
    encoded_pairs = []
    if re.search(r"(?i)%27", url):
        encoded_pairs.append((url, re.sub(r"(?i)%27", "%2527", url)))
    else:
        separator = "&" if urlparse(url).query else "?"
        encoded_pairs.append((
            "{}{}_behavior_probe=%27".format(url, separator),
            "{}{}_behavior_probe=%2527".format(url, separator),
        ))

    for single_encoded_url, double_encoded_url in encoded_pairs:
        _single_response, single_metrics = await _request(
            client, policy, "GET", single_encoded_url
        )
        _double_response, double_metrics = await _request(
            client, policy, "GET", double_encoded_url
        )
        if (
            single_metrics
            and double_metrics
            and single_metrics["status_code"] != double_metrics["status_code"]
        ):
            double_metrics = dict(double_metrics)
            double_metrics["single_encoding_reference"] = single_metrics
            findings.append(_finding(
                "encoding_bypass_candidate",
                url,
                _exact_request("GET", double_encoded_url),
                baseline,
                double_metrics,
                "Single and double URL encoding produced different response statuses. Verify whether intermediary and application decoding disagree in a way that bypasses routing, filtering, or authorization.",
            ))
            break

    parsed = urlparse(url)
    unicode_variants = []
    if re.search(r"(?i)/admin(?=/|$)", parsed.path):
        unicode_path = re.sub(r"(?i)/admin(?=/|$)", "/ádmin", parsed.path, count=1)
        unicode_variants.append(urlunparse(parsed._replace(path=unicode_path)))
    for variant in unicode_variants:
        _response, metrics = await _request(client, policy, "GET", variant)
        if metrics and metrics["status_code"] != baseline["status_code"]:
            if not any(
                finding.get("vuln_type") == "encoding_bypass_candidate"
                for finding in findings
            ):
                findings.append(_finding(
                    "encoding_bypass_candidate",
                    url,
                    _exact_request("GET", variant),
                    baseline,
                    metrics,
                    "Unicode path normalization changed the response status. Verify whether intermediary and application normalization disagree in a way that bypasses routing, filtering, or authorization.",
                ))
            break

    # F. HTTP/1.0 downgrade
    http10_metrics, http10_request = await _http10_request(url, policy)
    if http10_metrics and _structure(http10_metrics) != _structure(baseline):
        findings.append(_finding(
            "http_version_behavior_difference",
            url,
            http10_request,
            baseline,
            http10_metrics,
            "The HTTP/1.0 response structure differs from HTTP/1.1 behavior. Verify whether proxy normalization, authentication, caching, or routing changes across protocol versions.",
        ))

    return findings
