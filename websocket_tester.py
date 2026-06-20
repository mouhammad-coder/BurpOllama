"""Authorized WebSocket security checks with conservative proof requirements."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from finding_model import normalize_finding
from security_hardening import redact_secrets

try:
    import websockets
except ImportError:  # pragma: no cover - uvicorn[standard] normally supplies it
    websockets = None


STACK_TRACE_RE = re.compile(
    r"(?i)(traceback|stack trace|exception at|typeerror:|referenceerror:|"
    r"at\s+[A-Za-z0-9_.$]+\s*\([^)]*:\d+:\d+\))"
)
SENSITIVE_RE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|(?:api[_-]?key|token|secret|password|"
    r"authorization|session)\s*[=:]\s*[\"']?[^,\s\"']{8,})"
)


def _finding(
    ws_url: str,
    vuln_type: str,
    severity: str,
    evidence: str,
    description: str,
    status: str,
    cwe: str,
    reproduction_steps: list[str],
) -> dict:
    return normalize_finding({
        "vuln_type": vuln_type,
        "title": vuln_type.replace("_", " ").title(),
        "url": ws_url,
        "affected_url": ws_url,
        "method": "WEBSOCKET",
        "severity": severity,
        "confidence": 90 if status == "confirmed" else 75,
        "exploitability_status": status,
        "evidence_strength": "strong" if status == "confirmed" else "moderate",
        "false_positive_risk": "low" if status == "confirmed" else "medium",
        "evidence": redact_secrets(evidence),
        "description": description,
        "business_impact": description,
        "reproduction_steps": reproduction_steps,
        "remediation": (
            "Authenticate the WebSocket handshake, validate Origin and negotiated "
            "subprotocols, and enforce strict message schemas and size limits."
        ),
        "cwe": cwe,
        "redaction_status": "redacted",
        "source": "websocket-security",
    })


async def _connect(ws_url: str, **kwargs):
    """Support both legacy and current websockets header argument names."""
    if websockets is None:
        raise RuntimeError("websockets dependency is not installed")
    try:
        return await websockets.connect(ws_url, open_timeout=8, close_timeout=3, **kwargs)
    except TypeError:
        if "additional_headers" in kwargs:
            kwargs["extra_headers"] = kwargs.pop("additional_headers")
        return await websockets.connect(ws_url, open_timeout=8, close_timeout=3, **kwargs)


async def _receive_messages(connection, limit: int = 10) -> list[str]:
    messages: list[str] = []
    for _ in range(limit):
        try:
            message = await asyncio.wait_for(connection.recv(), timeout=0.75)
        except (asyncio.TimeoutError, Exception):
            break
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        messages.append(str(message))
    return messages


async def test_websocket_security(
    ws_url: str,
    http_client: Any,
    scope_policy,
) -> list[dict]:
    """Test one discovered WebSocket URL. No request runs outside active scope."""
    del http_client  # kept for compatibility with hunt-engine client injection
    findings: list[dict] = []
    if websockets is None or not scope_policy.config.active_testing_enabled:
        return findings
    allowed, _reason = scope_policy.validate_target(ws_url, action="active")
    if not allowed:
        return findings

    # Missing authentication and sensitive-data checks share one anonymous session.
    try:
        allowed, _ = scope_policy.record_request(ws_url, action="active")
        if allowed:
            connection = await _connect(ws_url)
            try:
                messages = await _receive_messages(connection, 10)
                meaningful = [m for m in messages if m.strip() and m.strip().lower() not in {"ping", "pong"}]
                if meaningful:
                    findings.append(_finding(
                        ws_url, "ws_missing_auth", "HIGH",
                        "Anonymous WebSocket handshake succeeded; received: {}".format(
                            redact_secrets(meaningful[0][:500])
                        ),
                        "An unauthenticated client received application data from the WebSocket.",
                        "confirmed", "CWE-306",
                        [
                            "Connect to the WebSocket URL without cookies or authorization headers.",
                            "Wait for the initial server messages.",
                            "Confirm that application data is returned to the anonymous client.",
                        ],
                    ))
                for message in messages:
                    if SENSITIVE_RE.search(message) and redact_secrets(message) != message:
                        findings.append(_finding(
                            ws_url, "ws_sensitive_data_exposure", "HIGH",
                            "Sensitive pattern detected in server message: {}".format(
                                redact_secrets(message[:500])
                            ),
                            "The server transmitted a secret-like value in a WebSocket message.",
                            "confirmed", "CWE-200",
                            [
                                "Connect using an authorized controlled account.",
                                "Capture up to ten server messages.",
                                "Verify the redacted sensitive value is unnecessarily exposed.",
                            ],
                        ))
                        break

                test_messages = [
                    json.dumps({"__proto__": {"polluted": "burpollama_ws_test"}}),
                    "{malformed-json",
                    "A" * (1024 * 1024),
                ]
                for payload in test_messages:
                    try:
                        await connection.send(payload)
                        response = await asyncio.wait_for(connection.recv(), timeout=1.5)
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
                    response_text = (
                        response.decode("utf-8", errors="replace")
                        if isinstance(response, bytes) else str(response)
                    )
                    if STACK_TRACE_RE.search(response_text):
                        findings.append(_finding(
                            ws_url, "ws_input_validation", "HIGH",
                            "Payload type {} returned stack trace: {}".format(
                                "oversized" if len(payload) > 100000 else "malformed",
                                redact_secrets(response_text[:700]),
                            ),
                            "Malformed WebSocket input exposed an internal exception or stack trace.",
                            "confirmed", "CWE-20",
                            [
                                "Connect using an authorized test account.",
                                "Send the recorded non-destructive malformed message.",
                                "Observe the returned server exception without repeating the test.",
                            ],
                        ))
                        break
            finally:
                await connection.close()
    except Exception:
        pass

    # Cross-site WebSocket hijacking / Origin validation.
    try:
        allowed, _ = scope_policy.record_request(ws_url, action="active")
        if allowed:
            connection = await _connect(ws_url, origin="https://evil.com")
            try:
                findings.append(_finding(
                    ws_url, "ws_origin_not_validated", "MEDIUM",
                    "WebSocket handshake accepted Origin: https://evil.com",
                    "The endpoint accepted a cross-site Origin during the WebSocket handshake.",
                    "probable", "CWE-346",
                    [
                        "Connect to the WebSocket with Origin set to https://evil.com.",
                        "Observe that the handshake is accepted.",
                        "Manually verify whether authenticated browser cookies are usable cross-site.",
                    ],
                ))
            finally:
                await connection.close()
    except Exception:
        pass

    # Unknown subprotocol acceptance.
    try:
        allowed, _ = scope_policy.record_request(ws_url, action="active")
        if allowed:
            unexpected = "burpollama-unknown-protocol"
            connection = await _connect(ws_url, subprotocols=[unexpected])
            try:
                if getattr(connection, "subprotocol", None) == unexpected:
                    findings.append(_finding(
                        ws_url, "ws_protocol_confusion", "LOW",
                        "Server negotiated unexpected subprotocol: {}".format(unexpected),
                        "The server accepted an unrecognized WebSocket subprotocol.",
                        "probable", "CWE-20",
                        [
                            "Offer the unexpected test subprotocol during the handshake.",
                            "Inspect the negotiated Sec-WebSocket-Protocol value.",
                            "Confirm the server explicitly selected the unknown protocol.",
                        ],
                    ))
            finally:
                await connection.close()
    except Exception:
        pass

    return findings
