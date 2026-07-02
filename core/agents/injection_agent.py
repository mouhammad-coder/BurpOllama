"""Mode-gated injection specialist with evidence-backed SQL error detection."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext, observe_response
from core.evidence import write_evidence_artifact
from core.events import EventType


REQUEST_HEADERS = {
    "User-Agent": "BurpOllama Evidence Agent",
    "Accept": "*/*",
}

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"PostgreSQL.*ERROR",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ORA-\d{5}",
    r"SQLite/JDBCDriver",
    r"sqlite3\.OperationalError",
    r"unterminated quoted string",
    r"syntax error at or near",
    r"you have an error in your sql syntax",
]

SQL_PAYLOAD = "'"


def _raw_request(method: str, url: str) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in REQUEST_HEADERS.items()
    )
    return "{} {} HTTP/1.1\n{}".format(method.upper(), url, headers)


def _raw_response(response: httpx.Response, limit: int = 4096) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in response.headers.items()
    )
    return "HTTP/1.1 {}\n{}\n\n{}".format(
        response.status_code,
        headers,
        (response.text or "")[:limit],
    )


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _with_param(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out = []
    for key, original in params:
        if key == parameter:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, original))
    if not replaced:
        out.append((parameter, value))
    return urlunparse(parsed._replace(query=urlencode(out)))


def _sql_error(text: str) -> tuple[str, int]:
    for pattern in SQL_ERROR_PATTERNS:
        match = re.search(pattern, text or "", re.IGNORECASE)
        if match:
            return match.group(0), match.start()
    return "", -1


class InjectionAgent(BaseAgent):
    name = "injection"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        if context.options.mode == "passive":
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped active SQLi/SSTI/command payloads in passive mode",
                reason="passive_mode",
            )
            return []

        findings = []
        candidates = []
        for url in context.recon.get("urls", [])[:50]:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for parameter, original in params[:3]:
                await context.scheduler.checkpoint()
                if not context.scope.allows(url):
                    continue
                baseline_url = _with_param(url, parameter, original or "1")
                payload_url = _with_param(url, parameter, (original or "") + SQL_PAYLOAD)
                candidate = await self._test_sql_error(
                    context,
                    baseline_url,
                    payload_url,
                    parameter,
                )
                if candidate:
                    findings.append(candidate)
        context.raw_findings.extend(findings + candidates)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings + candidates:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Injection finding"),
                finding=finding,
            )
        return findings + candidates

    async def _test_sql_error(
        self,
        context: ScanContext,
        baseline_url: str,
        payload_url: str,
        parameter: str,
    ) -> dict | None:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            headers=REQUEST_HEADERS,
        ) as client:
            waited = await context.rate_limiter.acquire()
            if waited > 0.05:
                await context.emit(
                    EventType.THROTTLED,
                    agent=self.name,
                    phase=self.phase,
                    message="Rate limiter paused {:.2f}s".format(waited),
                )
            baseline = await client.get(baseline_url)
            await observe_response(
                context,
                baseline.status_code,
                agent=self.name,
                phase=self.phase,
                body_hint=getattr(baseline, "text", "")[:512],
            )
            context.tested_urls.add(baseline_url)
            waited = await context.rate_limiter.acquire()
            if waited > 0.05:
                await context.emit(
                    EventType.THROTTLED,
                    agent=self.name,
                    phase=self.phase,
                    message="Rate limiter paused {:.2f}s".format(waited),
                )
            await context.emit(
                EventType.REQUEST_TESTED,
                agent=self.name,
                phase=self.phase,
                message="GET {}".format(payload_url),
                method="GET",
                url=payload_url,
            )
            response = await client.get(payload_url)
            await observe_response(
                context,
                response.status_code,
                agent=self.name,
                phase=self.phase,
                body_hint=getattr(response, "text", "")[:512],
            )
            context.tested_urls.add(payload_url)
            await context.emit(
                EventType.RESPONSE_RECEIVED,
                agent=self.name,
                phase=self.phase,
                message="GET {} → HTTP {}".format(payload_url, response.status_code),
                method="GET",
                url=payload_url,
                status_code=response.status_code,
            )
        indicator, offset = _sql_error(response.text)
        baseline_indicator, _baseline_offset = _sql_error(baseline.text)
        if not indicator:
            return None
        baseline_clean = indicator.lower() not in (baseline.text or "").lower()
        confirmed = bool(baseline_clean and not baseline_indicator)
        artifact = write_evidence_artifact(
            context.scan,
            title="SQL error detected",
            url=payload_url,
            raw_request=_raw_request("GET", payload_url),
            raw_response=_raw_response(response),
            matched_indicator=indicator,
            indicator_location="response body, offset {}".format(offset),
            agent=self.name,
            vuln_class="SQL Injection",
            impact="SQL error disclosure may indicate injectable database-backed input.",
            fp_check=(
                "Baseline response did not contain the matched SQL error string."
                if confirmed
                else "SQL error also appeared in baseline or baseline check was inconclusive."
            ),
            confirmed=confirmed,
            filename_prefix="injection",
            metadata={
                "parameter": parameter,
                "baseline_url": baseline_url,
                "payload_url": payload_url,
                "baseline_status": baseline.status_code,
                "payload_status": response.status_code,
            },
        )
        confirmed = confirmed and _artifact_saved(artifact)
        return normalize_finding({
            "source": "injection-agent",
            "vuln_type": "SQL Injection",
            "title": "SQL error detected in parameter `{}`".format(parameter),
            "severity": "HIGH",
            "confidence": 92 if confirmed else 65,
            "url": payload_url,
            "method": "GET",
            "parameter": parameter,
            "description": "A SQL error string appeared only after the test payload was sent.",
            "evidence": indicator,
            "evidence_artifact": artifact,
            "business_impact": "SQL injection can expose or modify backend data if exploitation is confirmed.",
            "reproduction_steps": [
                "Send baseline GET {}.".format(baseline_url),
                "Send payload GET {}.".format(payload_url),
                "Confirm the payload response contains `{}` and baseline does not.".format(indicator),
            ],
            "remediation": "Use parameterized queries and validate input server-side.",
            "cwe": "CWE-89",
            "exploitability_status": "confirmed" if confirmed else "candidate",
            "evidence_strength": "strong" if confirmed else "weak",
            "false_positive_risk": "low" if confirmed else "medium",
            "redaction_status": "redacted",
        }, scan_id=context.scan["id"])
