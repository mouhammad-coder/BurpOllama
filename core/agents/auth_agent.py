"""Passive authentication surface observations."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"([A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)"
    r"(?![A-Za-z0-9_-])"
)
SENSITIVE_JWT_FIELDS = {"email", "role", "admin", "isAdmin", "user_id"}
SESSION_COOKIE_RE = re.compile(r"(sess|session|token|auth|jwt|sid)", re.I)


def _b64url_json(segment: str) -> dict | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def decode_jwt(token: str) -> dict | None:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    if header is None or payload is None:
        return None
    return {"header": header, "payload": payload}


def _redact_value(value):
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    text = str(value)
    return "<redacted>" if len(text) > 20 else value


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _header_items(headers) -> list[tuple[str, str]]:
    if not headers:
        return []
    if isinstance(headers, dict):
        return [(str(key), str(value)) for key, value in headers.items()]
    return [(str(key), str(value)) for key, value in headers]


def _cookie_headers(observation: dict) -> list[str]:
    values = [str(value) for value in observation.get("set_cookie_headers", []) if value]
    for key, value in _header_items(observation.get("headers", {})):
        if key.lower() == "set-cookie" and value:
            values.append(value)
    return values


def _observations(context: ScanContext) -> list[dict]:
    observed = []
    for key in (
        "http_observations",
        "observed_responses",
        "response_observations",
        "responses",
    ):
        value = context.recon.get(key, [])
        if isinstance(value, list):
            observed.extend(item for item in value if isinstance(item, dict))
    return observed


def _redact_jwts(text: str) -> str:
    return JWT_RE.sub("<jwt-redacted>", str(text or ""))


def _raw_response(observation: dict, body_limit: int = 1500) -> str:
    headers = "\n".join(
        "{}: {}".format(key, _redact_jwts(value))
        for key, value in _header_items(observation.get("headers", {}))
    )
    for value in observation.get("set_cookie_headers", []) or []:
        if "set-cookie:" not in value.lower():
            headers += ("\n" if headers else "") + "Set-Cookie: {}".format(
                _redact_jwts(value)
            )
    body = _redact_jwts(str(observation.get("body", "") or "")[:body_limit])
    status = observation.get("status_code") or observation.get("status") or "observed"
    return "HTTP/1.1 {}\n{}\n\n{}".format(status, headers, body)


def _raw_request(url: str) -> str:
    return "PASSIVE OBSERVATION {} HTTP/1.1".format(url or "unknown")


def _same_scope(context: ScanContext, value: str) -> bool:
    return context.scope.allows(value)


class AuthAgent(BaseAgent):
    name = "auth"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = []
        observations = _observations(context)
        findings.extend(await self._jwt_findings(context, observations))
        findings.extend(await self._cookie_findings(context, observations))
        findings.extend(await self._oauth_findings(context))

        auth_urls = [
            url for url in context.recon.get("urls", [])
            if any(term in url.lower() for term in (
                "login", "signin", "oauth", "authorize", "callback",
                "session", "password", "reset", "redirect_uri",
            ))
        ]
        message = (
            "{} passive auth observation(s), {} auth URL(s); no probes attempted".format(
                len(findings),
                len(auth_urls),
            )
            if findings or auth_urls
            else "No authentication endpoints observed"
        )
        await context.emit(
            EventType.SKIPPED if not findings and not auth_urls else EventType.LOG,
            agent=self.name,
            phase=self.phase,
            message=message,
            level="info",
        )
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Auth observation"),
                finding=finding,
            )
        return findings

    async def _jwt_findings(self, context: ScanContext, observations: list[dict]):
        findings = []
        seen = set()
        for observation in observations:
            url = str(observation.get("url") or context.scan.get("target") or "")
            sources = []
            for key, value in _header_items(observation.get("headers", {})):
                sources.append(("response header {}".format(key), value))
            for cookie in _cookie_headers(observation):
                sources.append(("Set-Cookie header", cookie))
            body = str(observation.get("body", "") or "")
            if body:
                sources.append(("response body", body))
            for location, text in sources:
                for match in JWT_RE.finditer(str(text or "")):
                    token = match.group(1)
                    decoded = decode_jwt(token)
                    if not decoded:
                        continue
                    dedupe = (url, location, token)
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    findings.extend(
                        self._build_jwt_findings(context, observation, url, location, token, decoded)
                    )
        return findings

    def _build_jwt_findings(
        self,
        context: ScanContext,
        observation: dict,
        url: str,
        location: str,
        token: str,
        decoded: dict,
    ) -> list[dict]:
        header = decoded["header"]
        payload = decoded["payload"]
        alg = str(header.get("alg", "")).lower()
        redacted_header = _redact_value(header)
        redacted_payload = _redact_value(payload)
        checks = []
        if alg == "none":
            checks.append((
                "JWT uses alg=none",
                "JWT Algorithm None Observation",
                "MEDIUM",
                70,
                "candidate",
                "weak",
                "medium",
                "JWT header declares alg=none. No token forgery or re-signing was attempted.",
            ))
        elif alg == "hs256":
            checks.append((
                "JWT uses HS256 shared-secret algorithm",
                "JWT HS256 Observation",
                "INFO",
                45,
                "candidate",
                "weak",
                "medium",
                "JWT header declares HS256. Common weak secrets were not tested.",
            ))
        if "exp" not in payload:
            checks.append((
                "JWT missing exp claim",
                "JWT Missing Expiration Claim",
                "INFO",
                55,
                "candidate",
                "weak",
                "medium",
                "JWT payload lacks an exp claim in passively observed token.",
            ))
        sensitive = [field for field in SENSITIVE_JWT_FIELDS if field in payload]
        if sensitive:
            checks.append((
                "JWT payload contains sensitive fields",
                "JWT Sensitive Payload Fields",
                "INFO",
                50,
                "candidate",
                "weak",
                "medium",
                "JWT payload includes sensitive field names: {}".format(", ".join(sorted(sensitive))),
            ))

        findings = []
        for title, vuln_type, severity, confidence, status, strength, fp_risk, fp_check in checks:
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=url,
                raw_request=_raw_request(url),
                raw_response=_raw_response(observation),
                matched_indicator=token[:20] + "...",
                indicator_location=location,
                agent=self.name,
                vuln_class=vuln_type,
                impact="JWT metadata may expose weak token configuration or sensitive claims.",
                fp_check=fp_check,
                confirmed=True,
                filename_prefix="auth-jwt",
                metadata={
                    "decoded_header": redacted_header,
                    "decoded_payload": redacted_payload,
                    "location": location,
                    "signature_verified": False,
                    "forgery_attempted": False,
                },
            )
            if not _artifact_saved(artifact):
                status = "candidate"
                strength = "weak"
                fp_risk = "high"
            findings.append(normalize_finding({
                "source": "passive-auth-agent",
                "vuln_type": vuln_type,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "url": url,
                "method": "PASSIVE",
                "description": fp_check,
                "evidence": "{} at {}".format(vuln_type, location),
                "evidence_artifact": artifact,
                "business_impact": "Review token configuration and avoid exposing sensitive claims.",
                "reproduction_steps": [
                    "Passively observe the response for {}.".format(url),
                    "Decode the JWT header and payload without validating or modifying the signature.",
                    "Confirm the listed claim or algorithm is present in the saved artifact.",
                ],
                "remediation": "Use signed JWT algorithms, short expirations, and avoid sensitive claim disclosure.",
                "cwe": "CWE-287",
                "exploitability_status": status,
                "evidence_strength": strength,
                "false_positive_risk": fp_risk,
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings

    async def _cookie_findings(self, context: ScanContext, observations: list[dict]):
        findings = []
        for observation in observations:
            url = str(observation.get("url") or context.scan.get("target") or "")
            target_https = urlparse(url).scheme == "https"
            for raw_cookie in _cookie_headers(observation):
                name = raw_cookie.split("=", 1)[0].strip()
                lower = raw_cookie.lower()
                missing = []
                if "httponly" not in lower:
                    missing.append("HttpOnly")
                if target_https and "secure" not in lower:
                    missing.append("Secure")
                if "samesite=" not in lower:
                    missing.append("SameSite")
                if "samesite=none" in lower and "secure" not in lower:
                    missing.append("Secure required with SameSite=None")
                if not missing:
                    continue
                session_like = bool(SESSION_COOKIE_RE.search(name))
                confidence = 85 if session_like and "Secure" in missing else 70
                title = "Session cookie missing security flags"
                artifact = write_evidence_artifact(
                    context.scan,
                    title=title,
                    url=url,
                    raw_request=_raw_request(url),
                    raw_response=_raw_response(observation),
                    matched_indicator=raw_cookie,
                    indicator_location="Set-Cookie header",
                    agent=self.name,
                    vuln_class="Session Cookie Missing Flags",
                    impact="Missing cookie flags can increase session theft or cross-site request risk.",
                    fp_check="Observed Set-Cookie header is missing: {}".format(", ".join(missing)),
                    confirmed=True,
                    filename_prefix="auth-cookie",
                    metadata={
                        "set_cookie": raw_cookie,
                        "cookie_name": name,
                        "missing_flags": missing,
                        "session_like_name": session_like,
                    },
                )
                status = "candidate"
                strength = "moderate" if _artifact_saved(artifact) else "weak"
                fp_risk = "low" if _artifact_saved(artifact) else "high"
                findings.append(normalize_finding({
                    "source": "passive-auth-agent",
                    "vuln_type": "Session Cookie Missing Flags",
                    "title": title,
                    "severity": "MEDIUM",
                    "confidence": confidence if _artifact_saved(artifact) else 50,
                    "url": url,
                    "method": "PASSIVE",
                    "description": "A Set-Cookie header is missing recommended security flags.",
                    "evidence": "Missing flags: {}".format(", ".join(missing)),
                    "evidence_artifact": artifact,
                    "business_impact": "Weak session cookie flags can make account compromise easier if paired with XSS or transport exposure.",
                    "reproduction_steps": [
                        "Passively observe the response for {}.".format(url),
                        "Inspect the Set-Cookie header in the saved artifact.",
                        "Confirm missing flags: {}.".format(", ".join(missing)),
                    ],
                    "remediation": "Set HttpOnly, Secure on HTTPS, and an explicit SameSite policy for session cookies.",
                    "cwe": "CWE-614",
                    "exploitability_status": status,
                    "evidence_strength": strength,
                    "false_positive_risk": fp_risk,
                    "redaction_status": "redacted",
                }, scan_id=context.scan["id"]))
        return findings

    async def _oauth_findings(self, context: ScanContext):
        findings = []
        for url in context.recon.get("urls", []):
            lowered = str(url).lower()
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not (
                "redirect_uri" in params
                or any(term in lowered for term in ("oauth", "authorize", "callback"))
            ):
                continue
            redirect_uri = params.get("redirect_uri", "")
            if not redirect_uri:
                continue
            redirect_parsed = urlparse(redirect_uri)
            reason = ""
            status = "candidate"
            confidence = 70
            if redirect_parsed.scheme != "https":
                reason = "redirect_uri is not HTTPS"
            elif not _same_scope(context, redirect_uri):
                reason = "redirect_uri domain differs from target scope"
                status = "needs_manual_validation"
                confidence = 65
            if not reason:
                continue
            artifact = write_evidence_artifact(
                context.scan,
                title="OAuth redirect_uri observation",
                url=url,
                raw_request=_raw_request(url),
                raw_response="PASSIVE URL OBSERVATION\n{}".format(url),
                matched_indicator=redirect_uri,
                indicator_location="query parameter redirect_uri",
                agent=self.name,
                vuln_class="OAuth Redirect URI Observation",
                impact="Weak redirect URI configuration can enable token leakage or authorization-code interception.",
                fp_check=reason,
                confirmed=True,
                filename_prefix="auth-oauth",
                metadata={
                    "redirect_uri": redirect_uri,
                    "reason": reason,
                    "followed_redirects": False,
                },
            )
            findings.append(normalize_finding({
                "source": "passive-auth-agent",
                "vuln_type": "OAuth Redirect URI Observation",
                "title": "OAuth redirect_uri observation",
                "severity": "MEDIUM",
                "confidence": confidence if _artifact_saved(artifact) else 50,
                "url": url,
                "method": "PASSIVE",
                "description": reason,
                "evidence": "redirect_uri={}".format(redirect_uri),
                "evidence_artifact": artifact,
                "business_impact": "Review OAuth client redirect URI allowlists and transport security.",
                "reproduction_steps": [
                    "Passively observe the URL.",
                    "Inspect the redirect_uri query parameter.",
                    "Do not follow or mutate the OAuth redirect chain.",
                ],
                "remediation": "Require HTTPS redirect URIs and strict allowlisting within the authorized application domain.",
                "cwe": "CWE-601",
                "exploitability_status": status,
                "evidence_strength": "moderate" if _artifact_saved(artifact) else "weak",
                "false_positive_risk": "medium" if _artifact_saved(artifact) else "high",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings
