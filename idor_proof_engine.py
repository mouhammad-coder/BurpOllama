from __future__ import annotations

import json
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from scope_policy import scope_policy
from utils import structural_json_diff


UUID_RE = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?![0-9a-f])"
)
NUMERIC_ID_RE = re.compile(r"(?<![A-Za-z0-9])\d+(?![A-Za-z0-9])")
MAX_EVIDENCE_CHARS = 2000


def _extract_ids(url: str) -> list[str]:
    parsed = urlsplit(url)
    searchable = "{}?{}".format(parsed.path, parsed.query)
    found: list[tuple[int, str]] = []
    uuid_matches = list(UUID_RE.finditer(searchable))
    uuid_spans = [match.span() for match in uuid_matches]
    found.extend((match.start(), match.group(0)) for match in uuid_matches)
    for match in NUMERIC_ID_RE.finditer(searchable):
        if any(start <= match.start() and match.end() <= end for start, end in uuid_spans):
            continue
        found.append((match.start(), match.group(0)))
    unique: list[str] = []
    for _position, value in sorted(found, key=lambda item: item[0]):
        if value not in unique:
            unique.append(value)
    return unique


def _uuid_offset(value: str, delta: int) -> str:
    original = uuid.UUID(value)
    adjusted = max(0, min((1 << 128) - 1, original.int + delta))
    return str(uuid.UUID(int=adjusted))


def _known_session_a_object(headers: dict, fallback: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() in {
            "x-burpollama-known-object-id",
            "x-burpollama-known-object-uuid",
        } and str(value).strip():
            return str(value).strip()
    return fallback


def _variants(value: str, known_session_a_object: str) -> list[tuple[str, str]]:
    try:
        numeric = int(value)
        candidates = [
            ("id-1", str(max(1, numeric - 1))),
            ("id+1", str(numeric + 1)),
            ("id+100", str(numeric + 100)),
        ]
    except ValueError:
        candidates = [
            ("id-1", _uuid_offset(value, -1)),
            ("id+1", _uuid_offset(value, 1)),
            ("id+100", _uuid_offset(value, 100)),
        ]
    candidates.extend([
        ("random_uuid", str(uuid.uuid4())),
        ("known_session_a_object", known_session_a_object),
    ])
    return candidates


def _replace_url_id(url: str, original: str, replacement: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path
    query = parsed.query
    if original in path:
        path = path.replace(original, replacement, 1)
    elif original in query:
        query = query.replace(original, replacement, 1)
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, parsed.fragment))


def _safe_headers(headers: dict) -> dict:
    return {
        str(key): str(value)
        for key, value in (headers or {}).items()
        if not str(key).lower().startswith("x-burpollama-")
    }


def _response_text(response: httpx.Response | None) -> str:
    if response is None:
        return ""
    return response.text[:MAX_EVIDENCE_CHARS]


def _redact_evidence(body: str, sensitive_keys: list[str]) -> str:
    redact_keys = {
        *(key.lower() for key in sensitive_keys),
        "password", "passwd", "secret", "token", "access_token",
        "refresh_token", "api_key", "private_key", "session_id",
    }
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        redacted = re.sub(
            r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "[REDACTED_EMAIL]",
            body,
        )
        redacted = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[REDACTED_JWT]",
            redacted,
        )
        return redacted[:MAX_EVIDENCE_CHARS]

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if str(key).lower() in redact_keys else redact(nested)
                for key, nested in value.items()
            }
        if isinstance(value, list):
            return [redact(nested) for nested in value]
        return value

    return json.dumps(redact(payload), ensure_ascii=True)[:MAX_EVIDENCE_CHARS]


def _safe_poc_url(url: str) -> str:
    parsed = urlsplit(url)
    secret_params = {"token", "access_token", "refresh_token", "api_key", "key", "session", "session_id"}
    query = urlencode([
        (key, "[REDACTED]" if key.lower() in secret_params else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _specific_data_point(body: str, sensitive_keys: list[str]) -> str:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return "a sensitive response field"

    def walk(value: Any) -> str:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.lower() in sensitive_keys and nested not in (None, "", [], {}):
                    return "{}=[REDACTED]".format(key)
                found = walk(nested)
                if found:
                    return found
        elif isinstance(value, list):
            for nested in value[:3]:
                found = walk(nested)
                if found:
                    return found
        return ""

    return walk(payload) or "a sensitive response field"


async def _get(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
) -> httpx.Response | None:
    allowed, _reason = scope_policy.record_request(url, action="authenticated")
    if not allowed:
        return None
    try:
        return await client.get(url, headers=headers)
    except httpx.HTTPError:
        return None


async def prove_idor(
    url: str,
    session_a_headers: dict,
    session_b_headers: dict,
    client: httpx.AsyncClient,
) -> dict:
    headers_a = _safe_headers(session_a_headers)
    headers_b = _safe_headers(session_b_headers)
    extracted_ids = _extract_ids(url)
    tested_ids: list[dict] = []
    best_a_response: httpx.Response | None = None
    best_sensitive_keys: list[str] = []
    proof_status = "not_vulnerable"

    response_b = await _get(client, url, headers_b)
    if response_b is None:
        return {
            "proof_status": proof_status,
            "tested_ids": tested_ids,
            "evidence_pair": {"session_b_response": "", "session_a_response": ""},
            "sensitive_keys_exposed": [],
            "reproduction_steps": [],
            "poc_curl": "curl -H 'Cookie: <SESSION_A_COOKIE>' '{}'".format(_safe_poc_url(url)),
        }

    # The same-resource Session A request is the decisive authorization check.
    response_a_same = await _get(client, url, headers_a)
    if response_a_same is not None:
        same_diff = structural_json_diff(response_b.text, response_a_same.text)
        same_sensitive = same_diff.get("sensitive_keys_found", [])
        tested_ids.append({
            "original_id": extracted_ids[0] if extracted_ids else "",
            "variant_type": "session_b_resource",
            "tested_value": extracted_ids[0] if extracted_ids else "",
            "url": url,
            "status": response_a_same.status_code,
        })
        if (
            response_a_same.status_code == 200
            and same_diff.get("keys_match")
            and same_diff.get("data_differs")
            and same_sensitive
        ):
            proof_status = "confirmed"
            best_a_response = response_a_same
            best_sensitive_keys = same_sensitive
        elif response_a_same.status_code == 200:
            proof_status = "probable"
            best_a_response = response_a_same
            best_sensitive_keys = same_sensitive
        elif response_b.status_code == 200 and response_a_same.status_code in (401, 403):
            proof_status = "inconsistent_enforcement"
            best_a_response = response_a_same

    for original_id in extracted_ids:
        known_session_a_object = _known_session_a_object(session_a_headers, original_id)
        for variant_type, tested_value in _variants(original_id, known_session_a_object):
            test_url = _replace_url_id(url, original_id, tested_value)
            response_a = response_a_same if test_url == url else await _get(client, test_url, headers_a)
            if response_a is None:
                tested_ids.append({
                    "original_id": original_id,
                    "variant_type": variant_type,
                    "tested_value": tested_value,
                    "url": test_url,
                    "status": None,
                })
                continue

            diff = structural_json_diff(response_b.text, response_a.text)
            sensitive = diff.get("sensitive_keys_found", [])
            tested_ids.append({
                "original_id": original_id,
                "variant_type": variant_type,
                "tested_value": tested_value,
                "url": test_url,
                "status": response_a.status_code,
                "keys_match": bool(diff.get("keys_match")),
                "data_differs": bool(diff.get("data_differs")),
                "sensitive_keys_found": sensitive,
            })

            if proof_status not in ("confirmed", "probable"):
                if response_b.status_code == 200 and response_a.status_code in (401, 403):
                    proof_status = "inconsistent_enforcement"
                    best_a_response = response_a

    evidence_a_raw = _response_text(best_a_response or response_a_same)
    evidence_b_raw = _response_text(response_b)
    evidence_a = _redact_evidence(evidence_a_raw, best_sensitive_keys)
    evidence_b = _redact_evidence(evidence_b_raw, best_sensitive_keys)
    specific_data_point = _specific_data_point(evidence_a, best_sensitive_keys)
    sensitive_label = ", ".join(best_sensitive_keys) if best_sensitive_keys else "sensitive fields"
    return {
        "proof_status": proof_status,
        "tested_ids": tested_ids,
        "evidence_pair": {
            "session_b_response": evidence_b,
            "session_a_response": evidence_a,
        },
        "sensitive_keys_exposed": best_sensitive_keys,
        "reproduction_steps": [
            "1. Authenticate as User B (victim)",
            "2. Send GET {} - observe {}".format(url, sensitive_label),
            "3. Replace session cookie with User A (attacker) session",
            "4. Send same request - observe User B data returned to User A",
            "5. Confirm: {} from User B visible to User A".format(specific_data_point),
        ],
        "poc_curl": "curl -H 'Cookie: <SESSION_A_COOKIE>' '{}'".format(_safe_poc_url(url)),
    }
