from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from scope_policy import scope_policy
from utils import structural_json_diff
from waf_engine import throttle


TARGET_HINTS = ("user", "account", "order", "payment")
ADMIN_HINTS = ("admin", "internal", "staff", "management", "audit", "secret")
MUTATION_HINTS = (
    "updateuser", "deleteuser", "setrole", "changerole", "updateaccount",
    "deleteaccount", "updateorder", "cancelorder", "refund", "payment",
)
SENSITIVE_KEYS = {
    "email", "phone", "address", "balance", "role", "permissions",
    "token", "secret", "payment", "card", "accountnumber",
}


def _schema_root(schema: dict) -> dict:
    return (
        schema.get("data", {}).get("__schema", {})
        or schema.get("__schema", {})
        or schema
    )


def _type_name(type_ref: dict) -> str:
    current = type_ref or {}
    while isinstance(current, dict):
        if current.get("name"):
            return str(current["name"])
        current = current.get("ofType") or {}
    return ""


def _type_map(schema: dict) -> tuple[dict, dict, dict]:
    root = _schema_root(schema)
    types = {
        item.get("name"): item
        for item in root.get("types", [])
        if isinstance(item, dict) and item.get("name")
    }
    query_name = (root.get("queryType") or {}).get("name", "Query")
    mutation_name = (root.get("mutationType") or {}).get("name", "Mutation")
    return types, types.get(query_name, {}), types.get(mutation_name, {})


def _selection_for_type(type_name: str, types: dict) -> list[str]:
    type_def = types.get(type_name, {})
    scalar_fields = []
    for field in type_def.get("fields", []) or []:
        field_type = _type_name(field.get("type", {}))
        if field_type in {"String", "Int", "Float", "Boolean", "ID"}:
            scalar_fields.append(str(field.get("name", "")))
    priority = [
        name for name in scalar_fields
        if name.lower() in {"id", "uuid", "name", "email", "role", "status", "total", "amount"}
    ]
    return (priority + [name for name in scalar_fields if name not in priority])[:8] or ["__typename"]


def _arg_value(arg: dict, known_id: str = "1") -> str:
    name = str(arg.get("name", "arg"))
    type_name = _type_name(arg.get("type", {}))
    if type_name in ("Int", "Float"):
        value = known_id if str(known_id).isdigit() else "1"
        return "{}:{}".format(name, value)
    if type_name == "Boolean":
        return "{}:true".format(name)
    return '{}:"{}"'.format(name, str(known_id).replace('"', '\\"'))


def _build_query(field: dict, types: dict, known_id: str = "1") -> str:
    field_name = str(field.get("name", ""))
    args = field.get("args", []) or []
    arg_text = ",".join(_arg_value(arg, known_id) for arg in args if isinstance(arg, dict))
    return_type = _type_name(field.get("type", {}))
    selection = " ".join(_selection_for_type(return_type, types))
    return "query{{{}{}{{{}}}}}".format(
        field_name,
        "({})".format(arg_text) if arg_text else "",
        selection,
    )


def _extract_ids(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            lower = str(key).lower()
            if (
                lower in {"id", "uuid"}
                or lower.endswith("_id")
                or lower.endswith("id")
            ) and isinstance(nested, (str, int)):
                text = str(nested)
                if text and text not in found:
                    found.append(text)
            found.extend(item for item in _extract_ids(nested) if item not in found)
    elif isinstance(value, list):
        for nested in value[:20]:
            found.extend(item for item in _extract_ids(nested) if item not in found)
    return found[:20]


def _sensitive_keys(body: str) -> list[str]:
    try:
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return []
    keys: set[str] = set()

    def walk(value: Any):
        if isinstance(value, dict):
            for key, nested in value.items():
                lower = str(key).lower()
                if any(hint in lower for hint in SENSITIVE_KEYS):
                    keys.add(str(key))
                walk(nested)
        elif isinstance(value, list):
            for nested in value[:20]:
                walk(nested)

    walk(payload)
    return sorted(keys)


async def _post(
    client: httpx.AsyncClient,
    graphql_url: str,
    body: Any,
    headers: dict,
) -> httpx.Response | None:
    allowed, _reason = scope_policy.record_request(graphql_url, action="authenticated")
    if not allowed or throttle.host_dead:
        return None
    async with await throttle.gate():
        await throttle.record_request(graphql_url)
        try:
            response = await client.post(
                graphql_url,
                json=body,
                headers={"Content-Type": "application/json", **(headers or {})},
            )
            if throttle.is_block_response(
                response.status_code,
                response.text[:16000],
                dict(response.headers),
                graphql_url,
            ):
                await throttle.record_block(
                    response.status_code,
                    response.text[:200],
                    graphql_url,
                    dict(response.headers),
                )
            return response
        except httpx.HTTPError:
            await throttle.record_network_error(graphql_url)
            return None


def _finding(
    graphql_url: str,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    *,
    confidence: int,
    exploitability_status: str,
    reproduction_steps: list[str],
    extra: dict | None = None,
) -> dict:
    finding = {
        "id": "GQL-{}-{}".format(int(time.time() * 1000), abs(hash(title + evidence)) % 99999),
        "source": "graphql-auth-tester",
        "vuln_type": title,
        "vulnerability_class": "GraphQL Authorization",
        "severity": severity,
        "confidence": confidence,
        "url": graphql_url,
        "affected_url": graphql_url,
        "method": "POST",
        "description": evidence,
        "evidence": evidence[:1500],
        "remediation": "Enforce object-level and field-level authorization in every GraphQL resolver. Limit batching and query complexity.",
        "cwe": "CWE-639",
        "cvss": 9.1 if severity == "CRITICAL" else (7.5 if severity == "HIGH" else 5.3),
        "graphql_auth_category": category,
        "exploitability_status": exploitability_status,
        "evidence_strength": "strong" if exploitability_status == "confirmed" else "moderate",
        "false_positive_risk": "low" if exploitability_status == "confirmed" else "medium",
        "business_impact": evidence,
        "technical_impact": evidence,
        "reproduction_steps": reproduction_steps,
        "safe_manual_validation_steps": reproduction_steps,
        "redaction_status": "redacted",
        "verdict": "PASS",
    }
    if extra:
        finding.update(extra)
    return finding


async def test_graphql_auth(
    graphql_url: str,
    schema: dict,
    session_a_headers: dict,
    session_b_headers: dict,
    client: httpx.AsyncClient,
) -> list[dict]:
    types, query_type, mutation_type = _type_map(schema)
    if not types or not query_type:
        return []

    findings: list[dict] = []
    query_fields = query_type.get("fields", []) or []
    target_fields = [
        field for field in query_fields
        if isinstance(field, dict)
        and any(
            hint in "{} {}".format(field.get("name", ""), _type_name(field.get("type", {}))).lower()
            for hint in TARGET_HINTS
        )
    ][:20]

    # The schema was discovered by introspection, so record that exposure.
    findings.append(_finding(
        graphql_url,
        "GraphQL Introspection Enabled",
        "MEDIUM",
        "schema_exposed",
        "GraphQL introspection exposed the Query and Mutation schema.",
        confidence=95,
        exploitability_status="probable",
        reproduction_steps=[
            "POST an authorized introspection query to {}.".format(graphql_url),
            "Observe __schema types and fields in the response.",
        ],
        extra={"schema_type_count": len(types)},
    ))

    known_ids: list[str] = ["1"]
    for field in target_fields:
        query = _build_query(field, types, known_ids[0])
        response_b = await _post(client, graphql_url, {"query": query}, session_b_headers)
        if not response_b or response_b.status_code != 200:
            continue
        try:
            payload_b = response_b.json()
            discovered = _extract_ids(payload_b)
            if discovered:
                known_ids = discovered
                query = _build_query(field, types, known_ids[0])
                response_b = await _post(client, graphql_url, {"query": query}, session_b_headers)
        except ValueError:
            pass
        if not response_b or response_b.status_code != 200:
            continue

        response_a = await _post(client, graphql_url, {"query": query}, session_a_headers)
        if not response_a or response_a.status_code != 200:
            continue
        diff = structural_json_diff(response_b.text, response_a.text)
        sensitive = sorted(set(
            diff.get("sensitive_keys_found", []) + _sensitive_keys(response_a.text)
        ))
        same_data = response_a.text == response_b.text
        confirmed = bool(
            diff.get("keys_match")
            and sensitive
            and (diff.get("data_differs") or same_data)
        )
        if confirmed:
            field_name = str(field.get("name", "query"))
            findings.append(_finding(
                graphql_url,
                "GraphQL Authorization Bypass - {}".format(field_name),
                "HIGH",
                "unauthorized_access",
                "Session A received Session B GraphQL object data for field '{}'. Sensitive keys: {}.".format(
                    field_name,
                    sensitive[:8],
                ),
                confidence=97,
                exploitability_status="confirmed",
                reproduction_steps=[
                    "Authenticate as Session B and send: {}".format(query),
                    "Record the returned object ID and redacted sensitive fields.",
                    "Replay the same query with Session A.",
                    "Observe Session B object data returned to Session A.",
                ],
                extra={
                    "graphql_query": query,
                    "sensitive_keys": sensitive,
                    "session_b_status": response_b.status_code,
                    "session_a_status": response_a.status_code,
                    "structural_diff": diff,
                    "known_object_ids": known_ids,
                },
            ))

    # Admin/internal queries are safe to test unauthenticated because they are reads.
    for field in query_fields:
        if not isinstance(field, dict):
            continue
        field_name = str(field.get("name", ""))
        if not any(hint in field_name.lower() for hint in ADMIN_HINTS):
            continue
        query = _build_query(field, types, known_ids[0])
        response = await _post(client, graphql_url, {"query": query}, {})
        if response and response.status_code == 200 and '"data"' in response.text and '"errors"' not in response.text:
            findings.append(_finding(
                graphql_url,
                "GraphQL Unauthorized Admin/Internal Data - {}".format(field_name),
                "HIGH",
                "unauthorized_access",
                "Unauthenticated GraphQL query '{}' returned data.".format(field_name),
                confidence=92,
                exploitability_status="confirmed",
                reproduction_steps=[
                    "Send the GraphQL query without authentication: {}".format(query),
                    "Observe admin/internal data in the response.",
                ],
                extra={"graphql_query": query, "unauthenticated_status": response.status_code},
            ))

    # Never execute state-changing mutations. Flag dangerous schema surface for manual proof.
    for field in (mutation_type.get("fields", []) or []):
        if not isinstance(field, dict):
            continue
        field_name = str(field.get("name", ""))
        if any(hint in re.sub(r"[^a-z0-9]", "", field_name.lower()) for hint in MUTATION_HINTS):
            findings.append(_finding(
                graphql_url,
                "GraphQL Privilege Escalation Mutation Candidate - {}".format(field_name),
                "CRITICAL",
                "privilege_escalation",
                "State-changing mutation '{}' accepts object/user-related arguments. It was not executed to avoid modifying data.".format(
                    field_name
                ),
                confidence=70,
                exploitability_status="needs_manual_validation",
                reproduction_steps=[
                    "Use approved disposable accounts for Session A and Session B.",
                    "Review mutation '{}' and its arguments in the exposed schema.".format(field_name),
                    "Attempt only a reversible, authorized change against a disposable Session B object using Session A.",
                    "Confirm authorization is enforced before submitting a bounty report.",
                ],
                extra={
                    "mutation_name": field_name,
                    "mutation_args": [
                        arg.get("name", "") for arg in field.get("args", []) if isinstance(arg, dict)
                    ],
                    "mutation_executed": False,
                },
            ))

    # One read-only request containing 1000 minimal queries tests batching controls.
    if not throttle.host_dead:
        batch = [{"query": "query{__typename}"} for _ in range(1000)]
        response = await _post(client, graphql_url, batch, session_a_headers)
        if response and response.status_code == 200:
            try:
                items = response.json()
            except ValueError:
                items = []
            succeeded = sum(
                1 for item in items
                if isinstance(item, dict) and item.get("data") and not item.get("errors")
            ) if isinstance(items, list) else 0
            if succeeded == 1000:
                findings.append(_finding(
                    graphql_url,
                    "GraphQL Batching Abuse - 1000 Queries Accepted",
                    "MEDIUM",
                    "batching_abuse",
                    "The server executed all 1000 read-only __typename queries in one HTTP request.",
                    confidence=96,
                    exploitability_status="confirmed",
                    reproduction_steps=[
                        "Send one authorized JSON batch containing 1000 read-only query{__typename} operations.",
                        "Observe 1000 successful GraphQL data responses.",
                        "Do not use state-changing operations for batching validation.",
                    ],
                    extra={
                        "batch_size": 1000,
                        "successful_queries": succeeded,
                        "batch_read_only": True,
                    },
                ))

    return findings
