"""Offline business-logic candidate classification.

This module never sends requests. It derives manual-testing candidates from
existing findings, recon URLs, content-discovery records, and schema endpoints.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse


PRICE_FIELDS = {"price", "amount", "quantity", "total", "cost"}
COUPON_HINTS = {"coupon", "promo", "discount", "voucher"}
CREATE_STEPS = {"create"}
FINAL_STEPS = {"complete", "confirm"}
BOUNDARY_SEGMENTS = {"user", "admin"}


def _url(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(
            item.get("url")
            or item.get("affected_url")
            or item.get("request_url")
            or ""
        )
    return ""


def _method(item: Any) -> str:
    return str(item.get("method", "")).upper() if isinstance(item, dict) else ""


def _walk_field_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            names.add(str(key).lower())
            names.update(_walk_field_names(nested))
    elif isinstance(value, list):
        for nested in value[:10]:
            names.update(_walk_field_names(nested))
    return names


def _parameter_names(item: dict) -> set[str]:
    names = {
        str(name).lower()
        for name in (item.get("params") or [])
        if str(name).strip()
    }
    parameter = item.get("parameter") or item.get("param")
    if parameter:
        names.add(str(parameter).lower())
    url = _url(item)
    if url:
        names.update(key.lower() for key in parse_qs(urlparse(url).query))
    for key in ("body", "json_body", "request_body", "poc_request_body", "exact_request_body"):
        names.update(_walk_field_names(item.get(key)))
    return names


def _endpoint_records(findings: list[dict], recon_data: dict) -> list[dict]:
    records: list[dict] = []
    for key in (
        "openapi_endpoints", "schema_endpoints", "endpoints",
        "content_discovery", "urls",
    ):
        for item in recon_data.get(key, []) or []:
            if isinstance(item, str):
                records.append({"url": item, "method": ""})
            elif isinstance(item, dict) and _url(item):
                records.append(dict(item))
    for finding in findings or []:
        if isinstance(finding, dict) and _url(finding):
            records.append(dict(finding))

    deduped = []
    seen = set()
    for record in records:
        body_fingerprint = json.dumps(
            record.get("body") or record.get("request_body") or {},
            sort_keys=True,
            default=str,
        )
        key = (_method(record), _url(record), body_fingerprint)
        if key not in seen:
            seen.add(key)
            deduped.append(record)
    return deduped


def _segments(url: str) -> list[str]:
    return [
        segment.lower()
        for segment in urlparse(url).path.split("/")
        if segment
    ]


def _step_key(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    normalized = [
        "{step}" if segment.lower() in CREATE_STEPS | FINAL_STEPS else segment.lower()
        for segment in parsed.path.split("/")
        if segment
    ]
    return parsed.netloc.lower(), "/" + "/".join(normalized)


def _boundary_key(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    normalized = [
        "{boundary}" if segment.lower() in BOUNDARY_SEGMENTS else segment.lower()
        for segment in parsed.path.split("/")
        if segment
    ]
    return parsed.netloc.lower(), "/" + "/".join(normalized)


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _size_pair(finding: dict) -> tuple[int, int] | None:
    containers = [finding]
    for key in ("evidence", "response_sizes", "comparison", "size_comparison"):
        value = finding.get(key)
        if isinstance(value, dict):
            containers.append(value)
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    containers.append(parsed)
            except ValueError:
                pass

    valid_keys = (
        "valid_response_size", "valid_size", "existing_user_size",
        "known_user_size", "success_size",
    )
    invalid_keys = (
        "invalid_response_size", "invalid_size", "unknown_user_size",
        "nonexistent_user_size", "failure_size",
    )
    for container in containers:
        valid = next(
            (_coerce_int(container.get(key)) for key in valid_keys if key in container),
            None,
        )
        invalid = next(
            (_coerce_int(container.get(key)) for key in invalid_keys if key in container),
            None,
        )
        if valid is not None and invalid is not None and valid != invalid:
            return valid, invalid

    text = " ".join(str(finding.get(key, "")) for key in (
        "evidence", "description", "technical_impact",
    ))
    valid_match = re.search(
        r"(?i)\bvalid(?:\s+username|\s+user)?[^0-9]{0,50}"
        r"(?:size|length|bytes)[^0-9]{0,15}(\d+)",
        text,
    )
    invalid_match = re.search(
        r"(?i)\binvalid(?:\s+username|\s+user)?[^0-9]{0,50}"
        r"(?:size|length|bytes)[^0-9]{0,15}(\d+)",
        text,
    )
    if valid_match and invalid_match:
        valid, invalid = int(valid_match.group(1)), int(invalid_match.group(1))
        if valid != invalid:
            return valid, invalid
    return None


def _candidate(
    category: str,
    url: str,
    description: str,
    steps: list[str],
    impact: str,
    risk_level: str,
    *,
    related_endpoints: list[str] | None = None,
    evidence: Any = None,
    parameter: str = "",
) -> dict:
    severity = "HIGH" if risk_level == "high_value" else (
        "MEDIUM" if risk_level == "medium_value" else "LOW"
    )
    digest = hashlib.sha256(
        "{}|{}|{}".format(category, url, related_endpoints or []).encode()
    ).hexdigest()[:16]
    return {
        "id": "BLC-{}".format(digest),
        "source": "business-logic-classifier",
        "title": category,
        "vuln_type": category,
        "vulnerability_class": "Business Logic",
        "url": url,
        "affected_url": url,
        "method": "MANUAL",
        "parameter": parameter,
        "severity": severity,
        "confidence": 65,
        "description": description,
        "manual_test_description": description,
        "safe_reproduction_steps": steps,
        "reproduction_steps": steps,
        "expected_impact": impact,
        "business_impact": impact,
        "technical_impact": description,
        "risk_level": risk_level,
        "related_endpoints": related_endpoints or [url],
        "evidence": json.dumps(evidence, ensure_ascii=False) if evidence is not None else description,
        "remediation": (
            "Enforce business invariants and authorization server-side. Model "
            "allowed state transitions explicitly and reject invalid repetitions, "
            "values, roles, and ordering."
        ),
        "cwe": "CWE-840",
        "exploitability_status": "needs_manual_validation",
        "evidence_strength": "weak",
        "false_positive_risk": "high",
        "redaction_status": "not_required",
        "triaged": False,
    }


def classify_business_logic_candidates(
    findings: list[dict],
    recon_data: dict,
) -> list[dict]:
    """Return offline business-logic candidates without issuing requests."""
    findings = findings or []
    recon_data = recon_data or {}
    records = _endpoint_records(findings, recon_data)
    candidates: list[dict] = []

    # 1. Price manipulation on known POST inputs.
    for record in records:
        if _method(record) != "POST":
            continue
        matched = sorted(_parameter_names(record) & PRICE_FIELDS)
        if not matched:
            continue
        url = _url(record)
        candidates.append(_candidate(
            "Price Manipulation Candidate",
            url,
            "POST input exposes price-sensitive field(s) {}. Verify that the server recalculates authoritative totals instead of trusting client values.".format(
                ", ".join(matched)
            ),
            [
                "Use a disposable cart, quote, or order containing a low-value test item.",
                "Record the normal server-calculated response without completing payment.",
                "Repeat with each identified field set to 0, -1, and a high-precision decimal such as 0.0001.",
                "Confirm whether the server rejects the value or independently recalculates it.",
                "Do not complete a real purchase or create financial loss.",
            ],
            "A confirmed issue could allow underpayment, free purchases, negative balances, or quantity/rounding abuse.",
            "high_value",
            evidence={"method": "POST", "parameters": matched},
            parameter=",".join(matched),
        ))

    # 2. Order-of-operations paths sharing the same workflow key.
    workflows: dict[tuple[str, str], dict[str, list[str]]] = {}
    for record in records:
        url = _url(record)
        segments = set(_segments(url))
        create = bool(segments & CREATE_STEPS)
        final = bool(segments & FINAL_STEPS)
        if not create and not final:
            continue
        bucket = workflows.setdefault(_step_key(url), {"create": [], "final": []})
        bucket["create" if create else "final"].append(url)
    for bucket in workflows.values():
        if not bucket["create"] or not bucket["final"]:
            continue
        endpoints = list(dict.fromkeys(bucket["create"] + bucket["final"]))
        candidates.append(_candidate(
            "Order-of-Operations Bypass Candidate",
            endpoints[0],
            "Related create and complete/confirm endpoints suggest a multi-step workflow whose state transitions require manual validation.",
            [
                "Use a disposable test object and record the expected create-to-confirm workflow.",
                "Attempt the confirm/complete action before the create or prerequisite step.",
                "Repeat a completed step once to check replay handling.",
                "Try omitting one intermediate step while preserving authorization.",
                "Stop before any irreversible payment, fulfillment, or external notification.",
            ],
            "A confirmed issue could bypass approval, payment, verification, inventory, or other mandatory workflow controls.",
            "high_value",
            related_endpoints=endpoints,
            evidence={"create_endpoints": bucket["create"], "final_endpoints": bucket["final"]},
        ))

    # 3. Coupon/discount stacking surfaces.
    for record in records:
        url = _url(record)
        hints = sorted(
            set(_segments(url)) & COUPON_HINTS
            | _parameter_names(record) & COUPON_HINTS
        )
        if not hints:
            continue
        candidates.append(_candidate(
            "Coupon or Discount Stacking Candidate",
            url,
            "The endpoint exposes coupon, promotion, discount, or voucher behavior that may permit repeated or combined application.",
            [
                "Use a disposable cart with a low-value test item and an approved test coupon.",
                "Apply the same coupon twice sequentially and inspect the calculated total.",
                "If supported, submit duplicate coupon values in one request.",
                "Test two promotions whose terms should be mutually exclusive.",
                "Do not place an order or consume a production-only voucher.",
            ],
            "A confirmed issue could allow unauthorized discounts, repeated credit, or promotion-limit bypass.",
            "medium_value",
            evidence={"matched_hints": hints},
            parameter=",".join(hints),
        ))

    # 4. Existing valid/invalid username response-size evidence.
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        pair = _size_pair(finding)
        blob = " ".join(str(finding.get(key, "")) for key in (
            "url", "parameter", "description", "evidence", "vuln_type",
        )).lower()
        if pair is None or not any(hint in blob for hint in ("user", "username", "email", "login", "account")):
            continue
        valid_size, invalid_size = pair
        candidates.append(_candidate(
            "Account Enumeration Oracle Candidate",
            _url(finding),
            "Existing evidence shows different response sizes for valid and invalid account identifiers ({} vs {} bytes). Validate whether size or timing reliably reveals account existence.".format(
                valid_size, invalid_size
            ),
            [
                "Use one approved test account identifier and one clearly nonexistent identifier.",
                "Send the same request a small number of times for each identifier.",
                "Compare status, normalized body size, message structure, and median response time.",
                "Confirm the difference is stable and not caused by caching or rate limiting.",
                "Do not enumerate real customer lists or automate broad username discovery.",
            ],
            "A confirmed oracle could enable targeted phishing, credential stuffing, password-reset abuse, or privacy exposure.",
            "medium_value",
            evidence={"valid_response_size": valid_size, "invalid_response_size": invalid_size},
        ))

    # 5. Matching actions under /user/ and /admin/.
    boundaries: dict[tuple[str, str], dict[str, list[str]]] = {}
    for record in records:
        url = _url(record)
        segments = set(_segments(url))
        roles = segments & BOUNDARY_SEGMENTS
        if not roles:
            continue
        bucket = boundaries.setdefault(_boundary_key(url), {"user": [], "admin": []})
        for role in roles:
            bucket[role].append(url)
    for bucket in boundaries.values():
        if not bucket["user"] or not bucket["admin"]:
            continue
        endpoints = list(dict.fromkeys(bucket["user"] + bucket["admin"]))
        candidates.append(_candidate(
            "Privilege Boundary Candidate",
            endpoints[0],
            "The same action appears under both user and admin route families. Verify server-side authorization with a low-privilege session.",
            [
                "Authenticate with an approved low-privilege disposable account.",
                "Perform the user-route action normally and record the request shape.",
                "Replay only the equivalent admin-route request with the same low-privilege session.",
                "Confirm the server denies access before returning or changing protected data.",
                "Use read-only or reversible test objects and do not modify real users.",
            ],
            "A confirmed issue could allow vertical privilege escalation or unauthorized administrative actions.",
            "high_value",
            related_endpoints=endpoints,
            evidence={"user_endpoints": bucket["user"], "admin_endpoints": bucket["admin"]},
        ))

    deduped = []
    seen = set()
    for candidate in candidates:
        key = (
            candidate["vuln_type"],
            candidate["url"],
            tuple(candidate.get("related_endpoints", [])),
            candidate.get("parameter", ""),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(candidate)
    return deduped
