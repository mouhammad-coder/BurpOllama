from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from scope_policy import scope_policy


TIMEOUT = httpx.Timeout(10.0)
USER_AGENT = "BurpOllama-SecretValidator/1.0"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: str) -> str:
    text = str(value or "")
    if len(text) <= 8:
        return "*" * len(text)
    visible = 4 if len(text) >= 16 else 2
    return "{}{}{}".format(text[:visible], "*" * (len(text) - visible * 2), text[-visible:])


def _result(
    secret_value: str,
    *,
    valid: bool,
    active: bool,
    account_info: str,
    poc_safe: str,
    reason: str = "",
) -> dict:
    result = {
        "valid": valid,
        "active": active,
        "scope": "read-only validated only",
        "account_info": account_info,
        "poc_safe": poc_safe,
        "redacted_value": _redact(secret_value),
        "severity_upgrade": bool(valid and active),
        "bounty_note": (
            "Secret is valid and active as of {}. Safe read-only call confirmed access."
            .format(_timestamp())
            if valid and active
            else "Secret was not confirmed active by the safe read-only validator."
        ),
    }
    if reason:
        result["reason"] = reason
    return result


def _scope_blocked(target_url: str) -> dict | None:
    allowed, _reason = scope_policy.validate_target(target_url, action="authenticated")
    if not allowed:
        return {"valid": "unvalidated", "reason": "scope_blocked"}
    return None


async def _request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | str | None = None,
) -> httpx.Response:
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        return await client.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
        )


def _jwt_part(value: str) -> dict:
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    parsed = json.loads(decoded.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _validate_jwt(secret_value: str) -> dict:
    try:
        header_part, payload_part, signature_part = secret_value.split(".", 2)
        header = _jwt_part(header_part)
        payload = _jwt_part(payload_part)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error):
        return _result(
            secret_value,
            valid=False,
            active=False,
            account_info="JWT structure invalid",
            poc_safe="Decode locally with a trusted JWT inspection tool; do not transmit the token.",
            reason="invalid_jwt",
        )

    algorithm = str(header.get("alg", "") or "").upper()
    now = int(datetime.now(timezone.utc).timestamp())
    exp = payload.get("exp")
    try:
        active = exp is None or int(exp) > now
    except (TypeError, ValueError):
        active = False
    signature_present = bool(signature_part)
    signature_validated = False
    reason = "signature_key_unavailable"
    if algorithm in ("", "NONE"):
        reason = "unsafe_or_missing_algorithm"

    return _result(
        secret_value,
        valid=signature_validated,
        active=active and signature_present and algorithm not in ("", "NONE"),
        account_info="JWT algorithm {}; signature not validated".format(algorithm or "missing"),
        poc_safe="Decode the JWT locally and verify it with the application's trusted signing key.",
        reason=reason,
    )


def _aws_credentials(secret_value: str) -> tuple[str, str, str]:
    parts = secret_value.split(":")
    if len(parts) < 2:
        return secret_value, "", ""
    return parts[0], parts[1], parts[2] if len(parts) > 2 else ""


def _aws_signed_headers(secret_value: str, body: str) -> tuple[dict, str] | None:
    access_key, secret_key, session_token = _aws_credentials(secret_value)
    if not access_key or not secret_key:
        return None
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    region = "us-east-1"
    service = "sts"
    host = "sts.amazonaws.com"
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_headers = "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{}\nx-amz-date:{}\n".format(
        host, amz_date
    )
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = "\n".join([
        "POST", "/", "", canonical_headers, signed_headers, payload_hash,
    ])
    credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, region, service)
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    key_date = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    key_region = sign(key_date, region)
    key_service = sign(key_region, service)
    signing_key = sign(key_service, "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}"
        .format(access_key, credential_scope, signed_headers, signature)
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers, access_key


async def validate_secret(secret_type: str, secret_value: str, context_url: str) -> dict:
    kind = str(secret_type or "").strip().lower()
    value = str(secret_value or "").strip()
    context = str(context_url or "").strip()

    if not value:
        return _result(
            value,
            valid=False,
            active=False,
            account_info="No secret value supplied",
            poc_safe="No proof command available.",
            reason="missing_secret",
        )

    if "jwt" in kind:
        return _validate_jwt(value)

    if "aws" in kind:
        target = "https://sts.amazonaws.com/"
        blocked = _scope_blocked(target)
        if blocked:
            return blocked
        signed = _aws_signed_headers(value, "Action=GetCallerIdentity&Version=2011-06-15")
        if signed is None:
            return _result(
                value,
                valid=False,
                active=False,
                account_info="AWS access key ID detected; secret key unavailable",
                poc_safe="aws sts get-caller-identity --profile <AUTHORIZED_READ_ONLY_PROFILE>",
                reason="missing_aws_secret_key",
            )
        headers, _access_key = signed
        try:
            response = await _request(
                "POST",
                target,
                headers=headers,
                data="Action=GetCallerIdentity&Version=2011-06-15",
            )
        except httpx.HTTPError:
            response = None
        valid = bool(response and response.status_code == 200)
        return _result(
            value,
            valid=valid,
            active=valid,
            account_info="AWS IAM identity" if valid else "AWS credential not confirmed",
            poc_safe="aws sts get-caller-identity --profile <AUTHORIZED_READ_ONLY_PROFILE>",
            reason="" if valid else "validation_failed",
        )

    provider = ""
    target = context
    method = "GET"
    headers: dict[str, str] = {}
    params = None
    poc_safe = ""
    if "github" in kind:
        provider = "GitHub"
        target = "https://api.github.com/user"
        headers = {"Authorization": "Bearer {}".format(value), "Accept": "application/vnd.github+json"}
        poc_safe = "curl -H 'Authorization: Bearer <REDACTED_TOKEN>' https://api.github.com/user"
    elif "slack" in kind:
        provider = "Slack"
        target = "https://slack.com/api/auth.test"
        headers = {"Authorization": "Bearer {}".format(value)}
        poc_safe = "curl -H 'Authorization: Bearer <REDACTED_TOKEN>' https://slack.com/api/auth.test"
    elif "stripe" in kind:
        provider = "Stripe"
        target = "https://api.stripe.com/v1/customers"
        headers = {"Authorization": "Bearer {}".format(value)}
        params = {"limit": "1"}
        poc_safe = "curl -u '<REDACTED_KEY>:' 'https://api.stripe.com/v1/customers?limit=1'"
    else:
        provider = "Generic API"
        if not context:
            return _result(
                value,
                valid=False,
                active=False,
                account_info="Generic API key context missing",
                poc_safe="Replay the original read-only request with a redacted key placeholder.",
                reason="missing_context_url",
            )
        headers = {"X-API-Key": value}
        poc_safe = "curl -H 'X-API-Key: <REDACTED_KEY>' '{}'".format(
            context.replace(value, "[REDACTED_KEY]")
        )

    blocked = _scope_blocked(target)
    if blocked:
        return blocked

    try:
        response = await _request(method, target, headers=headers, params=params)
    except httpx.HTTPError:
        response = None

    valid = bool(response and 200 <= response.status_code < 300)
    if valid and provider == "Slack":
        try:
            valid = bool(response.json().get("ok"))
        except (ValueError, AttributeError):
            valid = False
    return _result(
        value,
        valid=valid,
        active=valid,
        account_info="{} account".format(provider) if valid else "{} credential not confirmed".format(provider),
        poc_safe=poc_safe,
        reason="" if valid else "validation_failed",
    )
