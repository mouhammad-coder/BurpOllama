"""Read-only HTTP/1 request parsing differential probes.

These probes never append a second valid HTTP request. Every test uses a fresh
TLS connection with ``Connection: close`` and is reported only as a candidate.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
from urllib.parse import urlparse

import httpx

from finding_model import normalize_finding
from request_safety import execute_guarded_request


PROBE_TIMEOUT = 12.0
DELAY_THRESHOLD_SECONDS = 5.0


async def _baseline_request(
    base_url: str,
    client: httpx.AsyncClient,
    policy,
) -> dict:
    started = time.monotonic()
    response = await execute_guarded_request(
        client,
        policy,
        "GET",
        base_url,
        action="active",
        follow_redirects=False,
        timeout=httpx.Timeout(10.0),
    )
    if response is None:
        return {}
    return {
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "status_code": response.status_code,
        "response_size": len(response.content or b""),
        "timed_out": False,
    }


async def _raw_probe(
    base_url: str,
    request_bytes: bytes,
    policy,
) -> dict:
    allowed, _reason = policy.record_request(base_url, action="active")
    if not allowed:
        return {}

    parsed = urlparse(base_url)
    port = parsed.port or 443
    ssl_context = ssl._create_unverified_context()
    started = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                parsed.hostname,
                port,
                ssl=ssl_context,
                server_hostname=parsed.hostname,
            ),
            timeout=5.0,
        )
        writer.write(request_bytes)
        await writer.drain()
        raw = await asyncio.wait_for(
            reader.read(1_000_000),
            timeout=PROBE_TIMEOUT,
        )
        elapsed = time.monotonic() - started
        header_bytes, _, body = raw.partition(b"\r\n\r\n")
        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        status_match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", header_text)
        return {
            "elapsed_ms": round(elapsed * 1000, 2),
            "status_code": int(status_match.group(1)) if status_match else 0,
            "response_size": len(body),
            "timed_out": False,
            "response_excerpt": body.decode("utf-8", errors="replace")[:300],
        }
    except asyncio.TimeoutError:
        return {
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "status_code": 0,
            "response_size": 0,
            "timed_out": True,
            "response_excerpt": "",
        }
    except (OSError, ssl.SSLError):
        return {}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


def _request_bytes(host: str, headers: list[str], body: bytes) -> bytes:
    lines = [
        "POST / HTTP/1.1",
        "Host: {}".format(host),
        "User-Agent: BurpOllama-Smuggling-Timing-Probe/1.0",
        "Connection: close",
        *headers,
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii") + body


def _request_text(request_bytes: bytes) -> str:
    return request_bytes.decode("iso-8859-1", errors="replace")


def _delayed(baseline: dict, probe: dict) -> bool:
    return bool(
        baseline
        and probe
        and float(probe.get("elapsed_ms", 0))
        > float(baseline.get("elapsed_ms", 0)) + DELAY_THRESHOLD_SECONDS * 1000
    )


def _different(normal: dict, obfuscated: dict) -> bool:
    if not normal or not obfuscated:
        return False
    return bool(
        normal.get("timed_out") != obfuscated.get("timed_out")
        or normal.get("status_code") != obfuscated.get("status_code")
        or abs(
            int(normal.get("response_size", 0))
            - int(obfuscated.get("response_size", 0))
        ) > 50
        or abs(
            float(normal.get("elapsed_ms", 0))
            - float(obfuscated.get("elapsed_ms", 0))
        ) > 5000
    )


def _finding(
    base_url: str,
    candidate_type: str,
    exact_request: str,
    baseline: dict,
    probe: dict,
    comparison: dict | None = None,
) -> dict:
    manual_steps = (
        "Use Burp Suite Repeater with HTTP/1 to confirm. "
        "Never send actual smuggled requests in production."
    )
    timing_difference = round(
        float(probe.get("elapsed_ms", 0))
        - float(baseline.get("elapsed_ms", 0)),
        2,
    )
    evidence = {
        "exact_request": exact_request,
        "baseline": baseline,
        "probe": probe,
        "timing_difference_ms": timing_difference,
    }
    if comparison:
        evidence["comparison"] = comparison
    return normalize_finding({
        "source": "request-smuggling-detector",
        "title": candidate_type.replace("_", " ").upper(),
        "vuln_type": candidate_type,
        "vulnerability_class": candidate_type,
        "severity": "HIGH",
        "confidence": 72,
        "url": base_url,
        "affected_url": base_url,
        "method": "POST",
        "description": (
            "HTTP/1 parsing behavior differs under a bounded framing probe. "
            "Confirmation requires manual testing in Burp Suite."
        ),
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "exact_request": exact_request,
        "timing_difference_ms": timing_difference,
        "manual_steps": manual_steps,
        "manual_test_description": manual_steps,
        "note": "Confirmation requires manual testing in Burp Suite",
        "exploitability_status": "needs_manual_validation",
        "evidence_strength": "weak",
        "false_positive_risk": "high",
        "business_impact": (
            "If confirmed, request desynchronization could enable cache poisoning, "
            "credential capture, or cross-user request interference."
        ),
        "technical_impact": (
            "Front-end and back-end HTTP parsers may disagree about request boundaries."
        ),
        "remediation": (
            "Normalize HTTP framing at the edge, reject requests containing both "
            "Content-Length and Transfer-Encoding, reject obfuscated transfer encodings, "
            "and use one consistent HTTP parser across proxy layers."
        ),
        "cwe": "CWE-444",
        "reproduction_steps": [
            manual_steps,
            "Repeat the exact timing probe on an isolated authorized connection.",
            "Confirm parser disagreement without appending a second request.",
        ],
        "safe_manual_validation_steps": [
            manual_steps,
            "Test only an isolated lab or explicitly authorized staging target.",
            "Use Connection: close and never target another user's request.",
        ],
        "redaction_status": "not_required",
    })


async def detect_smuggling(
    base_url: str,
    client: httpx.AsyncClient,
    scope_policy,
) -> list[dict]:
    """Run safe HTTP/1 timing and transfer-encoding behavior probes."""
    policy = scope_policy
    parsed = urlparse(base_url)
    mode = policy.normalize_mode(policy.config.scan_mode)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or mode != "normal"
        or not policy.config.active_testing_enabled
        or policy.config.passive_only_mode
        or not policy.validate_target(base_url, action="active")[0]
    ):
        return []

    origin = "https://{}".format(parsed.netloc)
    baseline = await _baseline_request(origin + "/", client, policy)
    if not baseline:
        return []
    host = parsed.netloc
    findings = []

    # CL.TE: complete chunk terminator plus one inert byte, never a second request.
    cl_te = _request_bytes(
        host,
        ["Content-Length: 6", "Transfer-Encoding: chunked"],
        b"0\r\n\r\nX",
    )
    cl_te_result = await _raw_probe(origin, cl_te, policy)
    if _delayed(baseline, cl_te_result):
        findings.append(_finding(
            origin,
            "cl_te_candidate",
            _request_text(cl_te),
            baseline,
            cl_te_result,
        ))

    # TE.CL: valid single-byte chunk with a Content-Length that stops mid-frame.
    te_cl = _request_bytes(
        host,
        ["Content-Length: 4", "Transfer-Encoding: chunked"],
        b"1\r\nZ\r\n0\r\n\r\n",
    )
    te_cl_result = await _raw_probe(origin, te_cl, policy)
    if _delayed(baseline, te_cl_result):
        findings.append(_finding(
            origin,
            "te_cl_candidate",
            _request_text(te_cl),
            baseline,
            te_cl_result,
        ))

    # Obfuscated TE comparison against a normal empty chunked request.
    normal_te = _request_bytes(
        host,
        ["Transfer-Encoding: chunked"],
        b"0\r\n\r\n",
    )
    normal_result = await _raw_probe(origin, normal_te, policy)
    obfuscated_probes = [
        _request_bytes(host, ["Transfer-Encoding: xchunked"], b"0\r\n\r\n"),
        _request_bytes(host, ["Transfer-Encoding : chunked"], b"0\r\n\r\n"),
        _request_bytes(host, ["Transfer-Encoding:   chunked   "], b"0\r\n\r\n"),
    ]
    for obfuscated in obfuscated_probes:
        result = await _raw_probe(origin, obfuscated, policy)
        if _different(normal_result, result):
            findings.append(_finding(
                origin,
                "te_obfuscation",
                _request_text(obfuscated),
                baseline,
                result,
                {"normal_transfer_encoding": normal_result},
            ))
            break

    return findings
