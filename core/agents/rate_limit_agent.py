"""Rate-limit observations with passive defaults and bounded safe probes."""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
    "ratelimit-policy",
}
SENSITIVE_MARKERS = {
    "login": "login",
    "signin": "login",
    "sign-in": "login",
    "authenticate": "login",
    "auth": "login",
    "register": "register",
    "signup": "register",
    "sign-up": "register",
    "password": "password-reset",
    "reset": "password-reset",
    "forgot": "password-reset",
    "otp": "otp",
    "verify": "otp",
    "2fa": "otp",
    "mfa": "otp",
    "api/token": "token",
    "oauth/token": "token",
}
DESTRUCTIVE_MARKERS = {
    "payment", "payments", "checkout", "charge", "billing", "invoice/pay",
    "delete", "remove", "destroy", "transfer", "withdraw", "refund",
}
PROBE_LIMIT = 5


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


def _normalized_headers(headers) -> dict[str, str]:
    return {key.lower(): value for key, value in _header_items(headers)}


def _missing_rate_headers(headers) -> list[str]:
    present = set(_normalized_headers(headers))
    display = {
        "x-ratelimit-limit": "X-RateLimit-Limit",
        "x-ratelimit-remaining": "X-RateLimit-Remaining",
        "retry-after": "Retry-After",
        "ratelimit-policy": "RateLimit-Policy",
    }
    return [display[name] for name in sorted(RATE_LIMIT_HEADERS - present)]


def _has_rate_limit_headers(headers) -> bool:
    return bool(set(_normalized_headers(headers)) & RATE_LIMIT_HEADERS)


def _endpoint_type(url: str) -> str:
    parsed = urlparse(url)
    path = (parsed.path or "").lower().strip("/")
    for marker, label in SENSITIVE_MARKERS.items():
        if marker in path:
            return label
    return ""


def _safe_to_probe(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return not any(marker in path for marker in DESTRUCTIVE_MARKERS)


def _observations(context: ScanContext) -> list[dict]:
    observed = []
    for key in ("http_observations", "observed_responses", "response_observations"):
        value = context.recon.get(key, [])
        if isinstance(value, list):
            observed.extend(item for item in value if isinstance(item, dict))
    return observed


def _raw_request(url: str, method: str = "GET") -> str:
    return "{} {} HTTP/1.1\nUser-Agent: BurpOllama RateLimit Agent".format(
        method.upper(),
        url,
    )


def _raw_response(observation: dict) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value)
        for key, value in _header_items(observation.get("headers"))
    )
    return "HTTP/1.1 {}\n{}".format(
        observation.get("status_code") or observation.get("status") or "observed",
        headers,
    )


class RateLimitAgent(BaseAgent):
    name = "rate-limit"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = []
        passive_candidates = self._passive_findings(context)
        if context.options.mode == "passive":
            findings.extend(passive_candidates)
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped active rate-limit test in passive mode",
                reason="passive_mode",
            )
        else:
            findings.extend(await self._probe_findings(context, passive_candidates))

        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            if finding.get("exploitability_status") == "false_positive":
                continue
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Rate-limit observation"),
                finding=finding,
            )
        return findings

    def _passive_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        seen = set()
        for observation in _observations(context):
            url = str(observation.get("url") or "")
            if not url or not context.scope.allows(url):
                continue
            endpoint_type = _endpoint_type(url)
            if not endpoint_type:
                continue
            headers = observation.get("headers") or {}
            if _has_rate_limit_headers(headers):
                continue
            key = (url, endpoint_type)
            if key in seen:
                continue
            seen.add(key)
            missing = _missing_rate_headers(headers)
            artifact = write_evidence_artifact(
                context.scan,
                title="Sensitive endpoint lacks rate-limit headers",
                url=url,
                raw_request=_raw_request(url, str(observation.get("method") or "GET")),
                raw_response=_raw_response(observation),
                matched_indicator="missing rate-limit headers",
                indicator_location="response headers",
                agent=self.name,
                vuln_class="Rate Limit Missing Headers",
                impact="Sensitive auth flows should expose or enforce throttling to reduce abuse risk.",
                fp_check="Observed sensitive endpoint response without common rate-limit headers; no flooding was performed.",
                confirmed=False,
                filename_prefix="rate-limit-passive",
                metadata={
                    "endpoint_type": endpoint_type,
                    "observed_headers": dict(_header_items(headers)),
                    "missing_headers": missing,
                    "probe_performed": False,
                },
            )
            findings.append(normalize_finding({
                "source": "passive-rate-limit-agent",
                "vuln_type": "Rate Limit Missing Headers",
                "title": "Sensitive endpoint lacks rate-limit headers",
                "severity": "MEDIUM",
                "confidence": 55 if _artifact_saved(artifact) else 35,
                "url": url,
                "method": "PASSIVE",
                "description": "A {} endpoint was observed without rate-limit headers.".format(endpoint_type),
                "evidence": "Missing headers: {}".format(", ".join(missing)),
                "evidence_artifact": artifact,
                "business_impact": "Potential brute-force or abuse risk on sensitive authentication flow.",
                "remediation": "Apply throttling and return standard rate-limit headers for sensitive endpoints.",
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings

    async def _probe_findings(self, context: ScanContext, candidates: list[dict]) -> list[dict]:
        findings = []
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=context.options.timeout,
            headers={"User-Agent": "BurpOllama RateLimit Agent"},
        ) as client:
            for candidate in candidates:
                url = str(candidate.get("url") or "")
                if not _safe_to_probe(url):
                    findings.append(candidate)
                    continue
                snapshots = []
                for _index in range(PROBE_LIMIT):
                    waited = await context.rate_limiter.acquire()
                    if waited > 0.05:
                        await context.emit(
                            EventType.THROTTLED,
                            agent=self.name,
                            phase=self.phase,
                            message="Rate limiter paused {:.2f}s".format(waited),
                        )
                    start = time.monotonic()
                    try:
                        response = await client.get(url)
                        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
                        snapshots.append({
                            "status_code": response.status_code,
                            "elapsed_ms": elapsed_ms,
                            "headers": dict(response.headers),
                        })
                    except httpx.HTTPError as exc:
                        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
                        snapshots.append({
                            "status_code": None,
                            "elapsed_ms": elapsed_ms,
                            "error": type(exc).__name__,
                            "headers": {},
                        })
                findings.append(self._probe_result(context, candidate, snapshots))
        return findings

    def _probe_result(self, context: ScanContext, candidate: dict, snapshots: list[dict]) -> dict:
        url = str(candidate.get("url") or "")
        saw_429 = any(snapshot.get("status_code") == 429 for snapshot in snapshots)
        any_headers = any(_has_rate_limit_headers(snapshot.get("headers")) for snapshot in snapshots)
        all_soft_success = all(
            snapshot.get("status_code") in {200, 201, 400}
            for snapshot in snapshots
        )
        missing = _missing_rate_headers({})
        if saw_429:
            status = "false_positive"
            confidence = 20
            fp_risk = "low"
            evidence_strength = "moderate"
            title = "Rate limit observed during safe probe"
            fp_check = "Received HTTP 429 during five-request safe probe."
        elif len(snapshots) == PROBE_LIMIT and all_soft_success and not any_headers:
            status = "confirmed"
            confidence = 82
            fp_risk = "medium"
            evidence_strength = "moderate"
            title = "Sensitive endpoint lacks apparent rate limiting"
            fp_check = "Five-request safe probe returned no 429 and no rate-limit headers."
        else:
            status = "candidate"
            confidence = 60
            fp_risk = "medium"
            evidence_strength = "weak"
            title = "Sensitive endpoint rate limit needs review"
            fp_check = "Safe probe did not prove missing rate limiting conclusively."
        artifact = write_evidence_artifact(
            context.scan,
            title=title,
            url=url,
            raw_request=_raw_request(url),
            raw_response="SAFE RATE-LIMIT PROBE\n{}".format(snapshots),
            matched_indicator="{} response snapshots".format(len(snapshots)),
            indicator_location="bounded low-volume probe",
            agent=self.name,
            vuln_class="Rate Limit Missing Headers",
            impact="Sensitive endpoints without throttling may allow credential stuffing or OTP abuse.",
            fp_check=fp_check,
            confirmed=status == "confirmed",
            filename_prefix="rate-limit-probe",
            metadata={
                "probe_limit": PROBE_LIMIT,
                "responses": snapshots,
                "missing_headers": missing,
                "saw_429": saw_429,
            },
        )
        saved = _artifact_saved(artifact)
        if not saved and status == "confirmed":
            status = "candidate"
            confidence = 45
            evidence_strength = "weak"
            fp_risk = "high"
        return normalize_finding({
            "source": "passive-rate-limit-agent",
            "vuln_type": "Rate Limit Missing Headers",
            "title": title,
            "severity": "MEDIUM",
            "confidence": confidence,
            "url": url,
            "method": "GET",
            "description": fp_check,
            "evidence": "Probe statuses: {}".format(
                ", ".join(str(item.get("status_code")) for item in snapshots)
            ),
            "evidence_artifact": artifact,
            "business_impact": "Potential brute-force or abuse risk on sensitive authentication flow.",
            "remediation": "Apply throttling and return standard rate-limit headers for sensitive endpoints.",
            "exploitability_status": status,
            "evidence_strength": evidence_strength,
            "false_positive_risk": fp_risk,
            "redaction_status": "redacted",
        }, scan_id=context.scan["id"])
