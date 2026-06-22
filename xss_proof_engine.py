from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from scope_policy import scope_policy
from utils import extract_xss_context
from waf_engine import throttle
from request_safety import execute_guarded_request


EXECUTABLE_CONTEXTS = {"SCRIPT_TAG_CONTEXT", "EVENT_HANDLER_ATTRIBUTE"}


def _context_label(context: str) -> str:
    value = str(context or "").upper()
    for label in (
        "SCRIPT_TAG_CONTEXT",
        "EVENT_HANDLER_ATTRIBUTE",
        "HTML_ATTRIBUTE",
        "HTML_COMMENT",
        "RAW_HTML_CONTEXT",
    ):
        if label in value:
            return label
    return "UNKNOWN_CONTEXT"


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, current in pairs:
        if key == param and not replaced:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, current))
    if not replaced:
        updated.append((param, value))
    query = urlencode(updated)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    async with await throttle.gate():
        await throttle.record_request(url)
        response = await execute_guarded_request(
            client,
            scope_policy,
            "GET",
            url,
            action="active",
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


def _surrounding_quote(body: str, marker: str, context: str) -> str:
    marker_index = body.find(marker)
    if marker_index < 0:
        return ""
    if context == "HTML_ATTRIBUTE":
        prefix = body[:marker_index]
        match = re.search(r"\b[\w:-]+\s*=\s*([\"'])[^\"']*$", prefix, re.IGNORECASE)
        return match.group(1) if match else ""
    if context == "SCRIPT_TAG_CONTEXT":
        script_start = body.lower().rfind("<script", 0, marker_index)
        content_start = body.find(">", script_start, marker_index) if script_start >= 0 else -1
        prefix = body[content_start + 1:marker_index] if content_start >= 0 else body[:marker_index]
        double_count = len(re.findall(r'(?<!\\)"', prefix))
        single_count = len(re.findall(r"(?<!\\)'", prefix))
        if double_count % 2:
            return '"'
        if single_count % 2:
            return "'"
    return ""


def _payload_for_context(context: str, nonce: str, surrounding_quote: str = "") -> str:
    console_proof = 'try{console.log("burpollama_xss_proof_%s")}catch(e){}' % nonce
    if context == "SCRIPT_TAG_CONTEXT":
        return "{};{};//".format(surrounding_quote, console_proof)
    if context == "EVENT_HANDLER_ATTRIBUTE":
        return "try{document.title=`XSS_PROOF_%s`;console.log(`burpollama_xss_proof_%s`)}catch(e){}" % (
            nonce,
            nonce,
        )
    if context == "HTML_ATTRIBUTE":
        quote = surrounding_quote or '"'
        return '{}><span data-burpollama-xss-proof="burpollama_xss_proof_{}"></span>'.format(
            quote,
            nonce,
        )
    if context == "HTML_COMMENT":
        return '--><span data-burpollama-xss-proof="burpollama_xss_proof_{}"></span><!--'.format(nonce)
    return '<span data-burpollama-xss-proof="burpollama_xss_proof_{}"></span>'.format(nonce)


def _payload_in_correct_context(body: str, payload: str, context: str) -> bool:
    if payload not in body:
        return False
    escaped = re.escape(payload)
    if context == "SCRIPT_TAG_CONTEXT":
        return bool(re.search(r"<script\b[^>]*>[\s\S]*?" + escaped, body, re.IGNORECASE))
    if context == "EVENT_HANDLER_ATTRIBUTE":
        return bool(re.search(
            r"\bon\w+\s*=\s*([\"'])[^\"']*" + escaped + r"[^\"']*\1",
            body,
            re.IGNORECASE,
        ))
    if context == "HTML_ATTRIBUTE":
        return bool(re.search(
            r"\b[\w:-]+\s*=\s*([\"'])[^\"']*" + escaped,
            body,
            re.IGNORECASE,
        )) or 'data-burpollama-xss-proof=' in body
    if context == "HTML_COMMENT":
        return bool(re.search(r"<!--[\s\S]*?" + escaped, body, re.IGNORECASE))
    return payload in body


async def prove_xss(
    url: str,
    param: str,
    context: str,
    client: httpx.AsyncClient,
) -> dict:
    nonce = secrets.token_hex(4)
    marker = "burpollama_xss_{}".format(nonce)
    proof_marker = "burpollama_xss_proof_{}".format(nonce)
    context_label = _context_label(context)

    marker_url = _with_param(url, param, marker)
    marker_response = await _safe_get(client, marker_url)
    marker_html = bool(
        marker_response
        and marker_response.status_code == 200
        and "text/html" in marker_response.headers.get("content-type", "").lower()
        and marker in marker_response.text
    )
    detected_context = context_label
    if marker_html:
        marker_context = extract_xss_context(marker_response.text, marker)
        detected_context = _context_label(marker_context)
        if context_label == "UNKNOWN_CONTEXT":
            context_label = detected_context

    surrounding_quote = _surrounding_quote(
        marker_response.text if marker_response else "",
        marker,
        context_label,
    )
    harmless_payload = _payload_for_context(context_label, nonce, surrounding_quote)
    safe_poc_url = _with_param(url, param, harmless_payload)
    proof_response = await _safe_get(client, safe_poc_url) if marker_html else None
    proof_reflected = bool(
        proof_response
        and proof_response.status_code == 200
        and "text/html" in proof_response.headers.get("content-type", "").lower()
        and proof_marker in proof_response.text
        and _payload_in_correct_context(proof_response.text, harmless_payload, context_label)
    )

    if proof_reflected and context_label in EXECUTABLE_CONTEXTS:
        proof_status = "confirmed"
    elif proof_reflected:
        proof_status = "probable"
    else:
        proof_status = "context_only"

    severity = "HIGH" if context_label in EXECUTABLE_CONTEXTS else "MEDIUM"
    return {
        "proof_status": proof_status,
        "injection_context": context_label,
        "harmless_payload": harmless_payload,
        "reflection_confirmed": proof_reflected,
        "safe_poc_url": safe_poc_url,
        "reproduction_steps": [
            "1. Open the affected URL in an authorized test browser.",
            "2. Set parameter '{}' to the harmless proof payload.".format(param),
            "3. Load the generated safe proof URL.",
            "4. Confirm marker '{}' is reflected in {}.".format(
                proof_marker,
                context_label,
            ),
            "5. Verify only the harmless console/title proof occurs; no data is modified.",
        ],
        "cve_note": (
            "Reflected XSS - harmless proof payload confirmed in {}".format(context_label)
            if proof_reflected
            else "Reflected input identified in {}; harmless proof payload was not confirmed.".format(
                context_label
            )
        ),
        "severity": severity,
    }
