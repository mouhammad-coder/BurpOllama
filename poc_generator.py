"""Safe, read-only proof-of-concept guidance for findings and exploit chains."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _safe_get_url(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    query = urlencode([
        (name, "{test_value}") for name, _value in parse_qsl(
            parsed.query, keep_blank_values=True
        )
    ])
    return urlunsplit(("", "", parsed.path or "/", query, ""))


def _idor_variant(path: str) -> str:
    replaced = re.sub(r"(?<=/)\d+(?=/|$)", "{other_test_object_id}", path, count=1)
    if replaced == path:
        replaced = re.sub(
            r"(?i)(id=)[^&]+", r"\1{other_test_object_id}", path, count=1
        )
    return replaced


def generate_safe_poc(finding: dict) -> dict:
    """Return non-destructive validation steps; never emit write actions."""
    finding = finding or {}
    vuln_type = str(
        finding.get("vuln_type") or finding.get("title") or "Finding"
    )
    lower = vuln_type.lower()
    url = str(finding.get("affected_url") or finding.get("url") or "/")
    safe_path = _safe_get_url(url)
    original_method = str(finding.get("method") or "GET").upper()
    method = "GET" if original_method in STATE_CHANGING_METHODS else original_method
    if method not in {"GET", "HEAD", "OPTIONS"}:
        method = "GET"

    prerequisites = [
        "Use only accounts and records created for this authorized test.",
        "Do not access, modify, or retain real user data.",
    ]
    if any(term in lower for term in ("idor", "bola", "access control")):
        changed = _idor_variant(safe_path)
        steps = [
            f"1. Send {method} {safe_path} using test account A.",
            f"2. Change only the controlled test object identifier: {changed}.",
            "3. Repeat the read-only request using a record owned by test account B.",
            "4. Confirm only whether access is blocked; redact any returned data.",
        ]
        expected = "The server should deny access to the other controlled test object's data."
    elif "open redirect" in lower:
        steps = [
            f"1. Send {method} {safe_path} with a harmless reserved-domain destination.",
            "2. Use https://example.invalid/ as the destination.",
            "3. Observe the Location header without following the redirect.",
        ]
        expected = "The server should reject or normalize the untrusted destination."
    elif any(term in lower for term in ("sql injection", "nosql", "ssti")):
        steps = [
            f"1. Send the baseline read-only request: {method} {safe_path}.",
            "2. Replace one test parameter with a harmless syntax marker.",
            "3. Compare status, response shape, and timing without extracting records.",
        ]
        expected = "The response should remain stable and expose no parser error or extra data."
    elif any(term in lower for term in ("xss", "crlf", "host header")):
        steps = [
            f"1. Send the read-only request: {method} {safe_path}.",
            "2. Supply a unique plain-text marker with no executable script.",
            "3. Check whether the marker is safely encoded in the response.",
        ]
        expected = "The marker should be encoded and must not alter content or headers."
    elif any(term in lower for term in ("ssrf", "xxe", "command", "rce")):
        steps = [
            f"1. Send the baseline read-only request: {method} {safe_path}.",
            "2. Use only a controlled non-routable or authorized callback marker.",
            "3. Observe response differences; do not target internal systems.",
        ]
        expected = "The server should reject the marker and perform no outbound action."
    else:
        steps = [
            f"1. Reproduce the read-only request: {method} {safe_path}.",
            "2. Change one harmless test value at a time.",
            "3. Compare only status, headers, and redacted response structure.",
        ]
        expected = "The application should preserve authorization and respond safely."

    return {
        "vulnerability": vuln_type,
        "poc_steps": steps,
        "example_request": f"{method} {safe_path}",
        "expected_result": expected,
        "prerequisites": prerequisites,
        "safety": "Read-only, non-destructive, controlled test data only.",
    }


def generate_chain_poc(findings: list[dict]) -> list[str]:
    output: list[str] = []
    for finding in findings or []:
        poc = generate_safe_poc(finding)
        first_step = poc["poc_steps"][0].split(". ", 1)[-1]
        output.append(
            "{}. {} Validate {} without modifying server state.".format(
                len(output) + 1, first_step, poc["vulnerability"]
            )
        )
    output.append(
        "{}. Correlate only redacted observations; do not access real users, "
        "reuse credentials, or perform state-changing actions.".format(len(output) + 1)
    )
    return output
