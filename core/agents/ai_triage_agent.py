"""Optional local Ollama triage over saved evidence artifacts.

AI enriches candidate findings only. It never confirms, rejects, promotes, or
demotes a finding; the proof gate remains the authority.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

import httpx

from core.agents.base import BaseAgent, ScanContext
from core.config import ollama_config, ollama_health
from core.events import EventType


TRIAGE_STATUSES = {"candidate", "needs_manual_validation", "probable"}
ALLOWED_EXPLOITABILITY = {"high", "medium", "low", "unlikely"}
ALLOWED_FP_RISK = {"high", "medium", "low"}


def _artifact_path(finding: dict) -> Path | None:
    artifact = finding.get("evidence_artifact") or {}
    if not isinstance(artifact, dict):
        return None
    path = str(artifact.get("artifact_path") or artifact.get("path") or "").strip()
    return Path(path) if path else None


def _method_and_safe_url(raw_request: str, fallback_url: str) -> str:
    first = (raw_request or "").splitlines()[0] if raw_request else ""
    method = "GET"
    url = fallback_url
    parts = first.split()
    if len(parts) >= 2:
        method = re.sub(r"[^A-Z]", "", parts[0].upper()) or "GET"
        url = parts[1]
    parsed = urlparse(url if "://" in url else fallback_url)
    path = parsed.path or "/"
    params = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    safe = path
    if params:
        safe += "?" + "&".join("{}=<redacted>".format(name) for name in params)
    return "{} {}".format(method, safe)


def _strip_sensitive_headers(text: str) -> str:
    redacted_lines = []
    for line in (text or "").splitlines():
        if re.match(r"(?i)^\s*(authorization|cookie|set-cookie|x-api-key|api-key)\s*:", line):
            name = line.split(":", 1)[0]
            redacted_lines.append("{}: <redacted>".format(name))
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def build_ollama_triage_prompt(finding: dict, artifact: dict) -> str:
    raw_response = _strip_sensitive_headers(str(artifact.get("raw_response") or ""))[:512]
    request_summary = _method_and_safe_url(
        str(artifact.get("raw_request") or ""),
        str(artifact.get("url") or finding.get("url") or ""),
    )
    payload = {
        "task": "Triage this security candidate. Return JSON only.",
        "rules": [
            "Do not confirm or deny the finding.",
            "Use concise one-sentence fields.",
            "Base comments only on the provided evidence.",
        ],
        "finding": {
            "vuln_class": artifact.get("vuln_class") or finding.get("vuln_type"),
            "url": artifact.get("url") or finding.get("url"),
            "request": request_summary,
            "matched_indicator": artifact.get("matched_indicator"),
            "indicator_location": artifact.get("indicator_location"),
            "impact": artifact.get("impact"),
            "fp_check": artifact.get("fp_check"),
            "raw_response_first_512": raw_response,
        },
        "json_schema": {
            "exploitability": "high|medium|low|unlikely",
            "false_positive_risk": "high|medium|low",
            "recommended_action": "one sentence",
            "triage_note": "one sentence reason",
        },
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    return text[:3200]


def _parse_ollama_json(text: str) -> dict | None:
    cleaned = re.sub(r"```json\s*|```\s*", "", text or "").strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    exploitability = str(data.get("exploitability", "")).lower()
    fp_risk = str(data.get("false_positive_risk", "")).lower()
    if exploitability not in ALLOWED_EXPLOITABILITY or fp_risk not in ALLOWED_FP_RISK:
        return None
    return {
        "exploitability": exploitability,
        "false_positive_risk": fp_risk,
        "recommended_action": str(data.get("recommended_action") or "")[:240],
        "triage_note": str(data.get("triage_note") or "")[:240],
        "provider": "ollama",
    }


class AITriageAgent(BaseAgent):
    name = "ai-triage"
    phase = "ai_triage"

    async def run(self, context: ScanContext):
        if not context.scan.get("ai", {}).get("agents_enabled"):
            return await self._manual_review_only(context, "AI disabled — manual review only")

        health = await ollama_health()
        if not health.get("running") or not health.get("model_available"):
            await context.log(
                "Ollama unavailable for evidence triage: {}".format(
                    health.get("setup") or health.get("error") or "not running"
                ),
                "warning",
                agent=self.name,
                phase=self.phase,
            )
            return await self._copy_with_null_triage(context)

        cfg = ollama_config()
        triaged = []
        reviewed = 0
        async with httpx.AsyncClient(timeout=cfg["timeout"]) as client:
            for finding in context.raw_findings:
                original_status = finding.get("exploitability_status")
                enriched = dict(finding)
                if str(original_status or "").lower() not in TRIAGE_STATUSES:
                    triaged.append(enriched)
                    continue
                artifact = self._load_artifact(enriched)
                if not artifact:
                    enriched["ai_triage"] = None
                    triaged.append(enriched)
                    continue
                prompt = build_ollama_triage_prompt(enriched, artifact)
                result = await self._ask_ollama(client, cfg, prompt, context)
                enriched["ai_triage"] = result
                enriched["exploitability_status"] = original_status
                if result:
                    reviewed += 1
                    await context.emit(
                        EventType.AI_TRIAGE,
                        agent=self.name,
                        phase=self.phase,
                        message="AI triage note for {}".format(
                            enriched.get("title") or enriched.get("vuln_type")
                        ),
                        finding_id=enriched.get("id"),
                        ai_triage=result,
                    )
                triaged.append(enriched)
        context.triaged_findings = triaged
        context.scan["triaged_findings"] = triaged
        context.scan["ai_triage_stats"] = {
            "provider": "ollama",
            "model": cfg["model"],
            "reviewed": reviewed,
            "total": len(context.raw_findings),
        }
        return triaged

    async def _manual_review_only(self, context: ScanContext, message: str):
        for finding in context.raw_findings:
            finding.setdefault("ai_triage", None)
            finding["triaged"] = False
            finding["ai_summary"] = message
            if finding.get("exploitability_status") not in {"confirmed", "probable"}:
                finding.setdefault("verdict", "NEEDS_MANUAL_REVIEW")
        context.triaged_findings = list(context.raw_findings)
        context.scan["triaged_findings"] = context.triaged_findings
        await context.emit(
            EventType.SKIPPED,
            agent=self.name,
            phase=self.phase,
            message=message,
            reason="no_provider",
        )
        return context.triaged_findings

    async def _copy_with_null_triage(self, context: ScanContext):
        triaged = []
        for finding in context.raw_findings:
            enriched = dict(finding)
            if str(enriched.get("exploitability_status") or "").lower() in TRIAGE_STATUSES:
                enriched["ai_triage"] = None
            triaged.append(enriched)
        context.triaged_findings = triaged
        context.scan["triaged_findings"] = triaged
        return triaged

    def _load_artifact(self, finding: dict) -> dict | None:
        path = _artifact_path(finding)
        if not path or not path.exists() or not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    async def _ask_ollama(self, client: httpx.AsyncClient, cfg: dict, prompt: str, context: ScanContext) -> dict | None:
        try:
            response = await client.post(
                cfg["base_url"] + "/api/chat",
                json={
                    "model": cfg["model"],
                    "stream": False,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return compact JSON only. Do not include chain-of-thought.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "options": {"temperature": 0.0, "num_predict": 180},
                },
            )
            response.raise_for_status()
            text = response.json().get("message", {}).get("content", "")
            return _parse_ollama_json(text)
        except Exception as exc:
            await context.log(
                "Ollama triage skipped: {}".format(type(exc).__name__),
                "warning",
                agent=self.name,
                phase=self.phase,
            )
            return None
