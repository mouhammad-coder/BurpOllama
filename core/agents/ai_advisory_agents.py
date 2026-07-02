"""Early optional AI advisors for ranking, hypotheses, strategy, and wording.

These agents are advisory only. They never send HTTP requests, never bypass
scope or rate limits, and never promote weak evidence to confirmed findings.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ai_provider import ai_router
from ai_privacy import ai_privacy_guard

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


HIGH_VALUE_KEYWORDS = {
    "api": 25,
    "user": 25,
    "users": 25,
    "account": 24,
    "profile": 20,
    "order": 24,
    "orders": 24,
    "payment": 30,
    "billing": 30,
    "invoice": 26,
    "admin": 28,
    "login": 20,
    "auth": 22,
    "token": 26,
    "graphql": 30,
    "upload": 24,
    "file": 18,
    "download": 18,
    "cart": 16,
    "basket": 18,
    "me": 22,
}


def _safe_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)[:5000]


def _short(text: str, fallback: str, limit: int = 180) -> str:
    value = str(text or "").strip()
    if not value:
        return fallback
    value = re.sub(r"(?is)<think>.*?</think>", "", value)
    value = re.sub(r"(?i)chain[- ]of[- ]thought.*", "", value)
    value = " ".join(value.split())
    return value[:limit].rstrip()


def _endpoint_score(url: str) -> int:
    parsed = urlparse(str(url))
    path = parsed.path.lower()
    score = 0
    for keyword, weight in HIGH_VALUE_KEYWORDS.items():
        if keyword in path:
            score += weight
    if re.search(r"/\d+(?:/|$)", path):
        score += 18
    if "{" in path and "}" in path:
        score += 20
    if parsed.query:
        score += 8
    return score


def _rank_urls(urls: list[str], limit: int = 10) -> list[dict]:
    ranked = []
    for url in sorted(set(str(u) for u in urls if u)):
        score = _endpoint_score(url)
        if score:
            ranked.append({"url": url, "score": min(score, 100)})
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[:limit]


def _hypotheses(urls: list[str]) -> list[dict]:
    out = []
    for url in sorted(set(str(u) for u in urls if u)):
        path = urlparse(url).path.lower()
        if re.search(r"/(?:users?|orders?|accounts?|invoices?)/?\d+", path):
            out.append({
                "url": url,
                "class": "IDOR/BOLA",
                "reason": "numeric object identifier appears user-specific",
                "proof_required": "Session A/B proof before confirmation",
            })
        elif any(key in path for key in ("/admin", "/dashboard", "/settings")):
            out.append({
                "url": url,
                "class": "Access control",
                "reason": "privileged-looking route discovered",
                "proof_required": "authorized role comparison",
            })
        elif any(key in path for key in ("/graphql", "/api/graphql")):
            out.append({
                "url": url,
                "class": "GraphQL authorization",
                "reason": "GraphQL endpoint can expose object-level access issues",
                "proof_required": "schema-aware, in-scope authorization proof",
            })
        elif any(key in path for key in ("/upload", "/files", "/download")):
            out.append({
                "url": url,
                "class": "File workflow",
                "reason": "file handling workflows often affect stored XSS or data exposure",
                "proof_required": "safe file-type and authorization validation",
            })
    return out[:12]


class AIAdvisoryAgent(BaseAgent):
    phase = "reconnaissance"

    async def _enabled(self, context: ScanContext) -> bool:
        return bool(context.scan.get("ai", {}).get("agents_enabled"))

    async def _complete(
        self,
        context: ScanContext,
        prompt: str,
        *,
        fallback: str,
        max_tokens: int = 220,
    ) -> str:
        if not await self._enabled(context):
            return fallback
        system = (
            "You are an advisory security scan agent. Give one concise, safe "
            "reasoning summary only. Do not include hidden chain-of-thought. "
            "Do not suggest out-of-scope, destructive, WAF-bypass, brute-force, "
            "or unauthorized active testing."
        )
        try:
            response = await ai_router.complete(
                ai_privacy_guard.redact(prompt, cloud=False),
                system=system,
                temperature=0.05,
                max_tokens=max_tokens,
                preferred_provider=context.options.ai_provider,
                api_key=context.options.api_key,
            )
        except Exception:
            return fallback
        if "No AI provider available" in response:
            return fallback
        return _short(response, fallback)

    async def _emit_ai(
        self,
        context: ScanContext,
        event_type: EventType,
        message: str,
        **data,
    ) -> None:
        await context.emit(
            event_type,
            agent=self.name,
            phase=self.phase,
            message=message,
            **data,
        )


class AIReconRanker(AIAdvisoryAgent):
    name = "ai-ranker"

    def __init__(self, stage: str = "recon"):
        self.stage = stage
        if stage == "target":
            self.phase = "target_check"

    async def run(self, context: ScanContext):
        if not await self._enabled(context):
            return []
        if self.stage == "target":
            fallback = (
                "target scope accepted; prioritize endpoint mapping before any "
                "active checks"
            )
            prompt = {
                "task": "initial target understanding and scope review",
                "target": context.scan.get("target"),
                "mode": context.options.mode,
                "scope": context.scope.to_dict(),
            }
            note = await self._complete(
                context,
                _safe_json(prompt),
                fallback=fallback,
                max_tokens=120,
            )
            await self._emit_ai(
                context,
                EventType.AI_NOTE,
                note,
                role="target_understanding",
            )
            return []

        urls = list(context.recon.get("urls", []))
        ranked = _rank_urls(urls)
        context.analysis["ai_endpoint_ranking"] = ranked
        context.scan.setdefault("analysis", {})["ai_endpoint_ranking"] = ranked
        top = ranked[0]["url"] if ranked else context.scan.get("target", "")
        fallback = "{} looks highest-value for access-control and workflow review".format(
            top
        )
        prompt = {
            "task": "rank endpoints by bounty value and safe testing priority",
            "target": context.scan.get("target"),
            "mode": context.options.mode,
            "ranked_candidates": ranked,
            "tech_stack": context.recon.get("tech_stack", []),
        }
        note = await self._complete(
            context,
            _safe_json(prompt),
            fallback=fallback,
            max_tokens=180,
        )
        await self._emit_ai(
            context,
            EventType.AI_NOTE,
            note,
            role="endpoint_ranking",
            ranked=ranked,
        )
        return ranked


class AIHypothesisAgent(AIAdvisoryAgent):
    name = "ai-hypothesis"

    async def run(self, context: ScanContext):
        if not await self._enabled(context):
            return []
        hypotheses = _hypotheses(context.recon.get("urls", []))
        context.analysis["ai_hypotheses"] = hypotheses
        context.scan.setdefault("analysis", {})["ai_hypotheses"] = hypotheses
        if not hypotheses:
            message = "no strong vulnerability hypothesis yet; continue safe passive evidence collection"
            await self._emit_ai(
                context,
                EventType.AI_HYPOTHESIS,
                message,
                hypotheses=[],
            )
            return []
        top = hypotheses[0]
        fallback = (
            "hypothesis: {} may indicate {} because {}; {}".format(
                top["url"],
                top["class"],
                top["reason"],
                top["proof_required"],
            )
        )
        prompt = {
            "task": "create concise vulnerability hypotheses from recon data",
            "hypotheses": hypotheses,
            "safety": "mark unproven issues as candidates only",
        }
        message = await self._complete(
            context,
            _safe_json(prompt),
            fallback=fallback,
            max_tokens=220,
        )
        await self._emit_ai(
            context,
            EventType.AI_HYPOTHESIS,
            message,
            hypotheses=hypotheses,
        )
        return hypotheses


class AIStrategyAgent(AIAdvisoryAgent):
    name = "ai-strategy"

    async def run(self, context: ScanContext):
        if not await self._enabled(context):
            return {}
        ranking = context.analysis.get("ai_endpoint_ranking") or _rank_urls(
            context.recon.get("urls", [])
        )
        hypotheses = context.analysis.get("ai_hypotheses") or []
        priority_classes = [
            "Security Headers",
            "CORS",
            "Session Security",
            "IDOR",
            "GraphQL Authorization",
            "XSS",
            "SQL Injection",
            "SSRF",
            "Rate Limiting",
        ]
        if any("IDOR" in h.get("class", "") for h in hypotheses):
            priority_classes.insert(0, priority_classes.pop(priority_classes.index("IDOR")))
        if any("GraphQL" in h.get("class", "") for h in hypotheses):
            priority_classes.insert(1, priority_classes.pop(priority_classes.index("GraphQL Authorization")))
        strategy = {
            "priority_classes": priority_classes,
            "top_urls": [item["url"] for item in ranking[:8]],
            "active_tests_allowed": bool(context.options.active),
            "safety_note": (
                "passive observations only"
                if not context.options.active
                else "active checks allowed only inside confirmed scope"
            ),
        }
        context.scan["ai_strategy"] = strategy
        prompt = {
            "task": "suggest next best safe tests",
            "strategy": strategy,
            "mode": context.options.mode,
            "scope": context.scope.to_dict(),
        }
        fallback = "{} checks ranked highest; {}".format(
            strategy["priority_classes"][0],
            strategy["safety_note"],
        )
        message = await self._complete(
            context,
            _safe_json(prompt),
            fallback=fallback,
            max_tokens=180,
        )
        await self._emit_ai(
            context,
            EventType.AI_STRATEGY,
            message,
            strategy=strategy,
        )
        return strategy


class AIFinalFindingsAdvisor(AIAdvisoryAgent):
    name = "ai-final-findings"
    phase = "final_findings"

    async def run(self, context: ScanContext):
        if not await self._enabled(context):
            return {}
        findings = context.scan.get("confirmed_findings") or context.triaged_findings
        if not findings:
            await self._emit_ai(
                context,
                EventType.AI_NOTE,
                "no evidence-backed findings yet; final findings should stay factual and manual-review oriented",
                role="final_findings_wording",
            )
            return {}
        summaries = [
            {
                "title": item.get("title") or item.get("vuln_type"),
                "severity": item.get("severity"),
                "url": item.get("affected_url") or item.get("url"),
                "proof": item.get("exploitability_status"),
            }
            for item in findings[:8]
        ]
        prompt = {
            "task": "suggest concise final finding wording after evidence exists",
            "findings": summaries,
            "rule": "do not invent evidence; say needs manual validation when proof is incomplete",
        }
        fallback = "final finding wording prepared from existing evidence only"
        wording = await self._complete(
            context,
            _safe_json(prompt),
            fallback=fallback,
            max_tokens=260,
        )
        context.scan["ai_final_findings_guidance"] = {
            "summary": wording,
            "findings_reviewed": len(summaries),
        }
        await self._emit_ai(
            context,
            EventType.AI_NOTE,
            wording,
            role="final_findings_wording",
            findings_reviewed=len(summaries),
        )
        return context.scan["ai_final_findings_guidance"]
