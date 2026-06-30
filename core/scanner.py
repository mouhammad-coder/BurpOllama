"""Direct multi-agent scanner shared by the CLI and optional FastAPI wrapper."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from attack_graph import build_attack_graph
from coverage_intelligence import compute_coverage
from finding_model import normalize_findings
from scope_policy import scope_policy
from zero_fp_gate import apply_zero_fp_gate

from core.agents import (
    AIHypothesisAgent,
    AIReconRanker,
    AIReportAgent,
    AIStrategyAgent,
    AITriageAgent,
    CrawlerAgent,
    HuntCoordinatorAgent,
    JavaScriptAgent,
    ReconAgent,
    ReportAgent,
)
from core.agents.base import ScanContext
from core.config import load_config
from core.events import EventType, ScanEvent, event_bus
from core.ratelimit import RateLimiter
from core.scheduler import ScanCancelled, Scheduler
from core.scope import ScanScope
from core.storage import scan_store


MODE_MAP = {
    "passive": "passive_only",
    "passive_only": "passive_only",
    "bounty": "conservative",
    "conservative": "conservative",
    "deep": "normal",
    "normal": "normal",
    "intensive_authorized": "normal",
}


@dataclass
class ScanOptions:
    mode: str = "passive"
    allowed_domains: list[str] = field(default_factory=list)
    concurrency: int = 5
    rate_limit: float = 2.0
    timeout: float = 10.0
    retries: int = 1
    ai_enabled: bool | None = None
    ai_provider: str = ""
    model: str = ""
    api_key: str = ""
    output: str = "reports"
    time_budget: int = 900
    max_urls: int = 100
    oob_server: str = ""
    no_external_tools: bool = False

    def __post_init__(self):
        mode = str(self.mode or "passive").lower()
        if mode not in MODE_MAP:
            raise ValueError("Unknown scan mode: {}".format(self.mode))
        self.mode = (
            "passive" if MODE_MAP[mode] == "passive_only"
            else "bounty" if MODE_MAP[mode] == "conservative"
            else "deep"
        )
        self.concurrency = max(1, min(int(self.concurrency), 20))
        self.rate_limit = max(0.1, min(float(self.rate_limit), 50.0))
        self.timeout = max(1.0, min(float(self.timeout), 120.0))
        self.retries = max(0, min(int(self.retries), 5))
        self.time_budget = max(1, min(int(self.time_budget), 7200))
        self.max_urls = max(1, min(int(self.max_urls), 2000))
        self.output = str(Path(self.output or "reports").expanduser())

    @property
    def internal_mode(self) -> str:
        return MODE_MAP[self.mode]

    @property
    def active(self) -> bool:
        return self.mode != "passive"

    def to_dict(self) -> dict:
        return asdict(self)


def _scan_id(target: str) -> str:
    host = (urlparse(target).hostname or "target").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", host).strip("-")[:30] or "target"
    return "{}-{}".format(
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        slug,
    )


class Scanner:
    PHASES = (
        ("target_check", "PHASE 1 — TARGET CHECK"),
        ("reconnaissance", "PHASE 2 — RECONNAISSANCE"),
        ("vulnerability_hunt", "PHASE 3 — VULNERABILITY HUNT"),
        ("ai_triage", "PHASE 4 — AI TRIAGE"),
        ("proof_validation", "PHASE 5 — PROOF VALIDATION"),
        ("report_export", "PHASE 6 — REPORT EXPORT"),
    )

    def __init__(self, store=scan_store):
        self.store = store
        self.active_contexts: dict[str, ScanContext] = {}

    def prepare(
        self,
        target: str,
        mode: str = "passive",
        *,
        authorization_confirmed: bool = False,
        api_key: str = "",
        allowed_domains: list[str] | None = None,
        concurrency: int = 5,
        rate_limit: float = 2.0,
        timeout: float = 10.0,
        retries: int = 1,
        ai_provider: str = "",
        ai_enabled: bool | None = None,
        model: str = "",
        output: str = "reports",
        time_budget: int = 900,
        max_urls: int = 100,
        oob_server: str = "",
        no_external_tools: bool = False,
    ) -> dict[str, Any]:
        load_config()
        options = ScanOptions(
            mode=mode,
            allowed_domains=list(allowed_domains or []),
            concurrency=concurrency,
            rate_limit=rate_limit,
            timeout=timeout,
            retries=retries,
            ai_enabled=ai_enabled,
            ai_provider=ai_provider,
            model=model,
            api_key=api_key,
            output=output,
            time_budget=time_budget,
            max_urls=max_urls,
            oob_server=oob_server,
            no_external_tools=no_external_tools,
        )
        if options.active and not authorization_confirmed:
            raise PermissionError(
                "Active scans require confirmation that you own the target "
                "or have written permission."
            )
        scope = ScanScope(target, options.allowed_domains)
        allowed_domains = [
            ("*." + rule.value if rule.kind == "wildcard" else rule.value)
            for rule in scope.rules
            if not rule.excluded and rule.kind in {"host", "wildcard"}
        ]
        blocked_domains = [
            ("*." + rule.value if rule.kind == "wildcard" else rule.value)
            for rule in scope.rules
            if rule.excluded and rule.kind in {"host", "wildcard"}
        ]
        allowed_url_patterns = [
            r"^{}".format(re.escape(rule.value.rstrip("/")))
            for rule in scope.rules
            if not rule.excluded and rule.kind == "url_prefix"
        ]
        blocked_url_patterns = [
            r"^{}".format(re.escape(rule.value.rstrip("/")))
            for rule in scope.rules
            if rule.excluded and rule.kind == "url_prefix"
        ]
        scope_policy.update(
            {
                "allowed_domains": allowed_domains,
                "blocked_domains": blocked_domains,
                "allowed_url_patterns": allowed_url_patterns,
                "blocked_url_patterns": blocked_url_patterns,
                "scan_mode": options.internal_mode,
                "active_testing_enabled": options.active,
                "passive_only_mode": not options.active,
                "max_requests_per_minute": max(1, int(options.rate_limit * 60)),
            },
            persist=False,
        )
        allowed, reason = scope_policy.validate_target(target, action="scan")
        if not allowed:
            raise PermissionError(reason)
        if ai_provider:
            os.environ["BURPOLLAMA_PREFERRED_AI_PROVIDER"] = ai_provider
        if model:
            provider = (ai_provider or "OLLAMA").upper().replace("-", "_")
            os.environ["{}_MODEL".format(provider)] = model

        scan_id = _scan_id(target)
        scan = {
            "id": scan_id,
            "target": target,
            "status": "queued",
            "phase": "queued",
            "started": datetime.now(timezone.utc).isoformat(),
            "finished": "",
            "requested_scan_mode": options.internal_mode,
            "mode": options.mode,
            "options": options.to_dict(),
            "scope": scope.to_dict(),
            "logs": [],
            "raw_findings": [],
            "triaged_findings": [],
            "report_paths": {},
            "agent_status": {},
            "blackboard": [],
            "ai": {
                "requested": ai_enabled,
                "agents_enabled": False,
                "active_provider": "none",
                "active_model": "none",
                "triage_capable": False,
            },
        }
        self.store.save(scan, [])
        return scan

    async def run(
        self,
        target: str,
        mode: str = "passive",
        *,
        authorization_confirmed: bool = False,
        event_callback=None,
        **kwargs,
    ) -> dict[str, Any]:
        scan = self.prepare(
            target,
            mode,
            authorization_confirmed=authorization_confirmed,
            **kwargs,
        )
        return await self.run_prepared(scan, event_callback=event_callback)

    async def run_prepared(
        self,
        scan: dict[str, Any],
        *,
        api_key: str = "",
        event_callback=None,
    ) -> dict[str, Any]:
        options_data = dict(scan.get("options", {}))
        if api_key:
            options_data["api_key"] = api_key
        options = ScanOptions(**options_data)
        scope = ScanScope(
            scan["target"],
            scan.get("scope", {}).get("allowed_domains", []),
        )
        scheduler = Scheduler(options.concurrency)
        context = ScanContext(
            scan=scan,
            options=options,
            events=event_bus,
            scheduler=scheduler,
            rate_limiter=RateLimiter(options.rate_limit),
            scope=scope,
            store=self.store,
        )
        self.active_contexts[scan["id"]] = context
        event_subscription = None
        if event_callback:
            def event_subscription(payload):
                if payload.get("scan_id") != scan["id"]:
                    return None
                return event_callback(payload)

            event_bus.subscribe(event_subscription)
        scan["status"] = "running"
        await self._configure_ai(context)
        self.store.save(scan, [])

        try:
            await asyncio.wait_for(
                self._run_phases(context),
                timeout=options.time_budget,
            )
            scan.update({
                "status": "complete",
                "phase": "complete",
                "finished": datetime.now(timezone.utc).isoformat(),
            })
            await context.emit(
                EventType.SCAN_COMPLETED,
                message="Scan complete",
                findings=len(context.triaged_findings),
            )
        except TimeoutError:
            scan.update({
                "status": "interrupted",
                "phase": "interrupted",
                "error": "Scan time budget of {}s exceeded".format(options.time_budget),
                "finished": datetime.now(timezone.utc).isoformat(),
            })
            if not context.triaged_findings:
                context.triaged_findings = list(context.raw_findings)
                scan["triaged_findings"] = context.triaged_findings
            await context.emit(
                EventType.SCAN_INTERRUPTED,
                message="Scan time budget exceeded; writing partial reports",
                time_budget=options.time_budget,
            )
            await self._safe_partial_report(context)
        except (ScanCancelled, asyncio.CancelledError, KeyboardInterrupt) as exc:
            scan.update({
                "status": "interrupted",
                "phase": "interrupted",
                "error": str(exc) or "Interrupted by user",
                "finished": datetime.now(timezone.utc).isoformat(),
            })
            if not context.triaged_findings:
                context.triaged_findings = list(context.raw_findings)
                scan["triaged_findings"] = context.triaged_findings
            await context.emit(
                EventType.SCAN_INTERRUPTED,
                message="Scan interrupted; writing partial reports",
            )
            await self._safe_partial_report(context)
        except Exception as exc:
            scan.update({
                "status": "failed",
                "phase": "failed",
                "error": str(exc),
                "finished": datetime.now(timezone.utc).isoformat(),
            })
            await context.emit(EventType.ERROR, message=str(exc))
            await self._safe_partial_report(context)
        finally:
            scan["agent_status"] = scheduler.snapshot()
            scan["rate_limiter"] = context.rate_limiter.snapshot()
            findings = context.triaged_findings or context.raw_findings
            self.store.save(scan, findings)
            if event_subscription:
                event_bus.unsubscribe(event_subscription)
            self.active_contexts.pop(scan["id"], None)
        return scan

    async def _run_phases(self, context):
        await self._phase(context, "target_check", self._target_check)
        await self._phase(context, "reconnaissance", self._recon)
        await self._phase(
            context, "vulnerability_hunt", self._vulnerability_hunt
        )
        await self._phase(context, "ai_triage", self._ai_triage)
        await self._phase(context, "proof_validation", self._proof_validation)
        await self._phase(context, "report_export", self._report_export)

    def start_background(
        self,
        target: str,
        mode: str = "passive",
        *,
        authorization_confirmed: bool = False,
        event_callback=None,
        **kwargs,
    ) -> tuple[dict[str, Any], asyncio.Task]:
        scan = self.prepare(
            target,
            mode,
            authorization_confirmed=authorization_confirmed,
            **kwargs,
        )
        return scan, asyncio.create_task(
            self.run_prepared(scan, event_callback=event_callback)
        )

    def stop(self, scan_id: str) -> bool:
        context = self.active_contexts.get(scan_id)
        if not context:
            return False
        context.scheduler.request_stop()
        return True

    async def _phase(self, context, phase_name, operation):
        title = dict(self.PHASES)[phase_name]
        context.scan["phase"] = phase_name
        await context.emit(
            EventType.PHASE_STARTED,
            phase=phase_name,
            message=title,
        )
        await context.scheduler.checkpoint()
        result = await operation(context)
        context.scan["agent_status"] = context.scheduler.snapshot()
        self.store.save(
            context.scan,
            context.triaged_findings or context.raw_findings,
        )
        await context.emit(
            EventType.PHASE_COMPLETED,
            phase=phase_name,
            message="{} completed".format(title),
        )
        return result

    async def _target_check(self, context):
        await context.emit(
            EventType.AGENT_STARTED,
            agent="recon",
            phase="target_check",
            message="Scope locked to {}".format(
                ", ".join(context.scope.allowed_domains)
            ),
        )
        await context.emit(
            EventType.AGENT_COMPLETED,
            agent="recon",
            phase="target_check",
            message="Target accepted by ScopePolicy",
        )
        if context.scan.get("ai", {}).get("agents_enabled"):
            await context.scheduler.run(
                "ai-ranker",
                lambda: AIReconRanker(stage="target").execute(context),
            )

    async def _recon(self, context):
        await context.scheduler.run(
            "recon", lambda: ReconAgent().execute(context)
        )
        await self._enforce_url_budget(context, agent="recon")
        await context.scheduler.run(
            "crawler", lambda: CrawlerAgent().execute(context)
        )
        await self._external_katana(context)
        await self._enforce_url_budget(context, agent="katana")
        await context.scheduler.run(
            "javascript", lambda: JavaScriptAgent().execute(context)
        )
        if context.options.active:
            await self._external_js_secret_scans(context)
            await self._external_nuclei(context)
        if context.scan.get("ai", {}).get("agents_enabled"):
            await context.scheduler.run(
                "ai-ranker",
                lambda: AIReconRanker(stage="recon").execute(context),
            )
            await context.scheduler.run(
                "ai-hypothesis",
                lambda: AIHypothesisAgent().execute(context),
            )
            await context.scheduler.run(
                "ai-strategy",
                lambda: AIStrategyAgent().execute(context),
            )

    async def _enforce_url_budget(self, context, *, agent: str) -> None:
        max_urls = int(getattr(context.options, "max_urls", 100) or 100)
        urls = list(dict.fromkeys(context.recon.get("urls", []) or []))
        if len(urls) <= max_urls:
            context.recon["urls"] = urls
            context.scan["recon"] = context.recon
            return
        kept = urls[:max_urls]
        skipped = urls[max_urls:]
        context.recon["urls"] = kept
        context.recon.setdefault("skipped_by_budget", []).extend(skipped)
        context.scan["recon"] = context.recon
        await context.emit(
            EventType.SKIPPED,
            agent=agent,
            phase="reconnaissance",
            message="URL budget kept {} of {} discovered URL(s)".format(
                len(kept),
                len(urls),
            ),
            reason="url_budget_exceeded",
            max_urls=max_urls,
            skipped_count=len(skipped),
        )

    async def _external_katana(self, context):
        if context.options.no_external_tools:
            await context.emit(
                EventType.SKIPPED,
                agent="katana",
                phase="reconnaissance",
                message="External tools disabled by --no-external-tools",
                reason="external_tools_disabled",
            )
            return
        from core.integrations.katana import run_katana

        output_dir = Path(context.options.output) / context.scan["id"] / "external"
        urls = await asyncio.to_thread(
            run_katana,
            context.scan["target"],
            context.scope,
            output_dir,
        )
        if not urls:
            await context.emit(
                EventType.SKIPPED,
                agent="katana",
                phase="reconnaissance",
                message="katana not available or no in-scope URLs discovered",
                reason="external_tool_skipped",
            )
            return
        existing = set(context.recon.get("urls", []))
        added = [url for url in urls if url not in existing]
        context.recon.setdefault("urls", []).extend(added)
        await context.emit(
            EventType.URL_DISCOVERED,
            agent="katana",
            phase="reconnaissance",
            message="katana discovered {} in-scope URL(s)".format(len(added)),
            count=len(added),
        )

    async def _external_js_secret_scans(self, context):
        if context.options.no_external_tools:
            await context.emit(
                EventType.SKIPPED,
                agent="secret-tools",
                phase="reconnaissance",
                message="External tools disabled by --no-external-tools",
                reason="external_tools_disabled",
            )
            return
        from core.integrations.gitleaks import scan_js_content as scan_gitleaks
        from core.integrations.trufflehog import scan_js_content as scan_trufflehog

        findings = []
        js_contents = context.recon.get("js_contents", {}) or {}
        if not isinstance(js_contents, dict):
            return
        for url, content in js_contents.items():
            if not isinstance(content, str) or not context.scope.allows(str(url)):
                continue
            findings.extend(await asyncio.to_thread(
                scan_trufflehog,
                content,
                context.scan["id"],
                str(url),
            ))
            findings.extend(await asyncio.to_thread(
                scan_gitleaks,
                content,
                context.scan["id"],
                str(url),
            ))
        if findings:
            context.raw_findings.extend(findings)
            context.scan["raw_findings"] = context.raw_findings
            for finding in findings:
                context.scheduler.state(str(finding.get("source") or "secret-tools")).findings += 1
                await context.emit(
                    EventType.FINDING_CANDIDATE,
                    agent=str(finding.get("source") or "secret-tools"),
                    phase="reconnaissance",
                    message=finding.get("title", "External secret finding"),
                    finding=finding,
                )

    async def _external_nuclei(self, context):
        if context.options.no_external_tools:
            return
        from core.integrations.nuclei import run_nuclei

        output_dir = Path(context.options.output) / context.scan["id"] / "external"
        findings = await asyncio.to_thread(
            run_nuclei,
            context.scan["target"],
            output_dir,
            "exposures/",
            context.scan,
        )
        if not findings:
            await context.emit(
                EventType.SKIPPED,
                agent="nuclei",
                phase="reconnaissance",
                message="nuclei not available or no exposure findings",
                reason="external_tool_skipped",
            )
            return
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state("nuclei").findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent="nuclei",
                phase="reconnaissance",
                message=finding.get("title", "Nuclei finding"),
                finding=finding,
            )

    async def _vulnerability_hunt(self, context):
        await HuntCoordinatorAgent().execute(context)

    async def _ai_triage(self, context):
        await context.scheduler.run(
            "ai-triage", lambda: AITriageAgent().execute(context)
        )

    async def _proof_validation(self, context):
        graph = build_attack_graph(context.triaged_findings)
        graph_data = graph.to_dict()
        coverage = compute_coverage(
            context.recon,
            context.triaged_findings,
            tested_urls=sorted(context.tested_urls),
        )
        gated = apply_zero_fp_gate(
            context.triaged_findings,
            context.scope.to_dict(),
            graph_data,
            tech_stack=context.recon.get("tech_stack", []),
            scan_context={"recon": context.recon},
        )
        context.analysis.update({
            "attack_graph": graph_data,
            "coverage": coverage,
            "zero_fp_gate": gated,
        })
        context.scan["analysis"] = context.analysis
        confirmed = gated.get("valid_bugs", [])
        candidates = (
            gated.get("needs_more_proof", [])
            + gated.get("candidates", [])
            + gated.get("informational", [])
        )
        context.scan["confirmed_findings"] = confirmed
        context.scan["candidate_findings"] = candidates
        for finding in confirmed:
            await context.emit(
                EventType.FINDING_CONFIRMED,
                agent="proof",
                phase="proof_validation",
                message=finding.get("title", "Confirmed finding"),
                finding=finding,
            )
        for finding in candidates:
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent="proof",
                phase="proof_validation",
                message=finding.get("title", "Finding needs proof"),
                finding=finding,
            )

    async def _report_export(self, context):
        if context.scan.get("ai", {}).get("agents_enabled"):
            await context.scheduler.run(
                "ai-report", lambda: AIReportAgent().execute(context)
            )
        await context.scheduler.run(
            "report", lambda: ReportAgent().execute(context)
        )

    async def _configure_ai(self, context) -> dict:
        from ai_provider import ai_router

        ai_router.reload_from_env()
        availability = await ai_router.availability()
        requested = context.options.ai_enabled
        enabled = bool(requested is not False and availability.get("triage_capable"))
        context.scan["ai"] = {
            "requested": requested,
            "agents_enabled": enabled,
            "triage_capable": bool(availability.get("triage_capable")),
            "active_provider": availability.get("active_provider", "none"),
            "active_model": availability.get("active_model", "none"),
            "ollama_running": bool(availability.get("ollama_running")),
            "ollama_models": availability.get("ollama_models", []),
        }
        if enabled:
            await context.emit(
                EventType.AI_NOTE,
                agent="ai-agent",
                phase="target_check",
                message="AI agents enabled from start: {} / {}".format(
                    context.scan["ai"]["active_provider"],
                    context.scan["ai"]["active_model"],
                ),
                role="startup",
            )
        else:
            await context.emit(
                EventType.SKIPPED,
                agent="ai-agent",
                phase="target_check",
                message="AI disabled — manual review only",
                reason=(
                    "disabled_by_user"
                    if requested is False
                    else "no_provider"
                ),
            )
        return context.scan["ai"]

    async def _safe_partial_report(self, context):
        try:
            if not context.analysis:
                context.analysis = {
                    "coverage": compute_coverage(
                        context.recon,
                        context.triaged_findings or context.raw_findings,
                        tested_urls=sorted(context.tested_urls),
                    )
                }
                context.scan["analysis"] = context.analysis
            await ReportAgent().execute(context)
        except Exception as exc:
            await context.emit(
                EventType.ERROR,
                agent="report",
                phase="report_export",
                message="Partial report failed: {}".format(exc),
            )


scanner = Scanner()
