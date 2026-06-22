"""Persistence-oriented server-side prototype pollution testing."""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from request_safety import execute_guarded_request

from finding_model import normalize_finding


TIMEOUT = httpx.Timeout(12.0)


def _json_keys(value: Any, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            path = "{}.{}".format(prefix, key) if prefix else str(key)
            keys.add(path)
            keys.update(_json_keys(nested, path))
    elif isinstance(value, list):
        for nested in value[:10]:
            keys.update(_json_keys(nested, prefix))
    return keys


def _structure(response: httpx.Response | None) -> dict:
    if response is None:
        return {}
    text = response.text or ""
    try:
        payload = response.json()
        keys = sorted(_json_keys(payload))
    except ValueError:
        keys = []
    return {
        "status_code": response.status_code,
        "response_size": len(response.content or b""),
        "json_keys": keys,
        "content_type": response.headers.get("content-type", "").split(";", 1)[0],
    }


def _changed(before: dict, after: dict) -> bool:
    if not before or not after:
        return False
    return bool(
        before.get("status_code") != after.get("status_code")
        or before.get("content_type") != after.get("content_type")
        or before.get("json_keys") != after.get("json_keys")
        or abs(
            int(before.get("response_size", 0))
            - int(after.get("response_size", 0))
        ) > 50
    )


async def _request(
    client: httpx.AsyncClient,
    policy,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    return await execute_guarded_request(
        client,
        policy,
        method,
        url,
        action="authenticated",
        mutation=str(method or "").upper() in {"PUT", "PATCH", "DELETE"},
        explicitly_approved=bool(
            getattr(policy.config, "authenticated_testing_enabled", False)
        ),
        timeout=TIMEOUT,
        follow_redirects=False,
        **kwargs,
    )


def _query_url(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _response_evidence(response: httpx.Response | None) -> dict:
    if response is None:
        return {}
    return {
        "status_code": response.status_code,
        "headers": {
            key: value for key, value in response.headers.items()
            if key.lower() not in {"set-cookie", "authorization"}
        },
        "body": (response.text or "")[:1500],
    }


def _finding(
    url: str,
    test_name: str,
    status: str,
    payload: Any,
    confirming_url: str,
    confirming_response: httpx.Response | None,
    before: dict,
    after: dict,
) -> dict:
    confirmed = status == "confirmed"
    title = (
        "Prototype Pollution - Persistence Confirmed"
        if confirmed else
        "Prototype Pollution Candidate - Structural Change"
    )
    impact = "Prototype pollution can enable XSS, DoS, or remote code execution in Node.js"
    return normalize_finding({
        "source": "prototype-pollution-tester",
        "title": title,
        "vuln_type": title,
        "vulnerability_class": "Prototype Pollution",
        "severity": "HIGH" if confirmed else "MEDIUM",
        "confidence": 98 if confirmed else 72,
        "url": url,
        "affected_url": url,
        "method": "POST/PUT",
        "description": (
            "A unique prototype pollution nonce persisted into a subsequent clean response."
            if confirmed else
            "The response structure changed after a prototype pollution payload and requires manual confirmation."
        ),
        "evidence": json.dumps({
            "test": test_name,
            "exact_pollution_payload": payload,
            "confirming_url": confirming_url,
            "confirming_response": _response_evidence(confirming_response),
            "before_structure": before,
            "after_structure": after,
        }, ensure_ascii=False),
        "exact_pollution_payload": payload,
        "confirming_response": _response_evidence(confirming_response),
        "prototype_pollution_test": test_name,
        "exploitability_status": (
            "confirmed" if confirmed else "probable"
        ),
        "evidence_strength": "strong" if confirmed else "moderate",
        "false_positive_risk": "low" if confirmed else "medium",
        "business_impact": impact,
        "technical_impact": impact,
        "remediation": (
            "Reject __proto__, prototype, and constructor keys recursively. "
            "Use null-prototype objects, safe merge libraries, schema validation, "
            "and patched framework/runtime dependencies."
        ),
        "cwe": "CWE-1321",
        "cvss": 8.1 if confirmed else 6.5,
        "reproduction_steps": [
            "Send the exact pollution payload to the affected JSON endpoint using an authorized disposable environment.",
            "Wait at least 500 milliseconds.",
            "Send a clean GET to the endpoint and application root.",
            "Observe the nonce or stable structural change recorded in the evidence.",
        ],
        "safe_manual_validation_steps": [
            "Use only a disposable local or explicitly authorized test environment.",
            "Restart the application after testing if global prototype state may persist.",
            "Do not use gadget payloads that execute code or affect other users.",
        ],
        "redaction_status": "not_required",
    })


async def test_prototype_pollution(
    url: str,
    client: httpx.AsyncClient,
    scope_policy,
) -> list[dict]:
    """Test JSON, query-string, and nested prototype pollution persistence."""
    policy = scope_policy
    if (
        not policy.config.active_testing_enabled
        or not policy.config.authenticated_testing_enabled
        or policy.config.passive_only_mode
        or not policy.validate_target(url, action="authenticated")[0]
    ):
        return []

    parsed = urlparse(url)
    root_url = "{}://{}/".format(parsed.scheme, parsed.netloc)
    baseline_endpoint = await _request(client, policy, "GET", url)
    baseline_root = await _request(client, policy, "GET", root_url)
    baseline_structures = {
        url: _structure(baseline_endpoint),
        root_url: _structure(baseline_root),
    }

    nonce = "burpollama_test_{}".format(secrets.token_hex(6))
    tests = [
        {
            "name": "json_body___proto__",
            "kind": "json",
            "payload": {"__proto__": {"polluted": nonce}},
        },
        {
            "name": "query___proto__",
            "kind": "query",
            "payload": {"__proto__[polluted]": nonce},
        },
        {
            "name": "query_constructor_prototype",
            "kind": "query",
            "payload": {"constructor[prototype][polluted]": nonce},
        },
        {
            "name": "nested_constructor_prototype",
            "kind": "json",
            "payload": {
                "constructor": {
                    "prototype": {
                        "polluted": nonce,
                    },
                },
            },
        },
    ]

    findings = []
    for test in tests:
        if test["kind"] == "json":
            # The integration only supplies schema-discovered POST/PUT JSON
            # endpoints. Try both accepted mutation verbs without following
            # redirects; unsupported methods are ignored.
            for method in ("POST", "PUT"):
                await _request(
                    client,
                    policy,
                    method,
                    url,
                    headers={"Content-Type": "application/json"},
                    json=test["payload"],
                )
        else:
            key, value = next(iter(test["payload"].items()))
            polluted_url = _query_url(url, key, value)
            await _request(client, policy, "GET", polluted_url)

        await asyncio.sleep(0.5)

        subsequent = [
            (url, await _request(client, policy, "GET", url)),
            (root_url, await _request(client, policy, "GET", root_url)),
        ]
        confirmed_pair = next(
            (
                (response_url, response)
                for response_url, response in subsequent
                if response is not None and nonce in (response.text or "")
            ),
            None,
        )
        if confirmed_pair:
            response_url, response = confirmed_pair
            findings.append(_finding(
                url,
                test["name"],
                "confirmed",
                test["payload"],
                response_url,
                response,
                baseline_structures.get(response_url, {}),
                _structure(response),
            ))
            break

        changed_pair = next(
            (
                (response_url, response)
                for response_url, response in subsequent
                if response is not None and _changed(
                    baseline_structures.get(response_url, {}),
                    _structure(response),
                )
            ),
            None,
        )
        if changed_pair:
            response_url, response = changed_pair
            findings.append(_finding(
                url,
                test["name"],
                "probable",
                test["payload"],
                response_url,
                response,
                baseline_structures.get(response_url, {}),
                _structure(response),
            ))
            break

    return findings
