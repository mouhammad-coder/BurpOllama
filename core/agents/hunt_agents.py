"""Controlled vulnerability-hunt coordinator and specialist ownership map."""

from __future__ import annotations

from adaptive_scan import ResourceController
from autonomous_planner import WorkingMemory
from coverage_intelligence import prioritize_urls
from finding_model import normalize_findings
from hunt_engine import run_hunt
from scope_policy import scope_policy

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


SPECIALIST_AGENTS = {
    "header": {
        "Security Headers", "CORS", "Session Security", "Clickjacking",
    },
    "auth": {
        "Auth Bypass", "JWT Analysis", "JWT Key Confusion", "OAuth Flow",
        "Session Security", "Default Credentials",
    },
    "access-control": {
        "IDOR", "GraphQL Authorization", "Business Logic", "Race Conditions",
    },
    "open-redirect": {"Open Redirect", "Open Redirect Candidate"},
    "ssrf": {"SSRF Candidate", "SSRF"},
    "injection": {
        "SQL Injection", "SSTI", "Path Traversal and LFI",
        "NoSQL Injection", "OS Command Injection", "CRLF Injection",
        "Host Header Injection", "XXE Candidates",
    },
    "xss": {
        "XSS", "Stored XSS", "DOM XSS", "Blind XSS", "CSRF",
        "Prototype Pollution", "Browser Storage Security",
    },
    "rate-limit": {"Rate Limiting"},
}


def agent_for_class(label: str) -> str:
    lowered = str(label or "").lower()
    for agent, classes in SPECIALIST_AGENTS.items():
        if any(name.lower() in lowered or lowered in name.lower() for name in classes):
            return agent
    return "hunt"


class HuntCoordinatorAgent(BaseAgent):
    name = "hunt"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        plan = context.scan.get("adaptive_plan", {})
        enabled = list(plan.get("enabled_modules", []))
        if context.options.mode == "passive":
            # Existing active detector engine remains disabled in passive mode.
            await self._passive_observations(context)
            return context.raw_findings

        scope_policy.update(
            {
                "allowed_domains": context.scope.allowed_domains,
                "scan_mode": context.options.internal_mode,
                "active_testing_enabled": True,
                "passive_only_mode": False,
                "max_requests_per_minute": max(
                    1, int(context.options.rate_limit * 60)
                ),
            },
            persist=False,
        )
        priority_classes = list(
            context.scan.get("ai_strategy", {}).get("priority_classes", [])
        )
        from core.agents.ssrf_agent import SSRFAgent

        await context.scheduler.run("ssrf", lambda: SSRFAgent().execute(context))
        passive_findings = list(context.raw_findings)

        def class_priority(module: str) -> int:
            lowered = str(module or "").lower()
            for index, item in enumerate(priority_classes):
                if item.lower() in lowered or lowered in item.lower():
                    return index
            return len(priority_classes) + 1

        enabled = sorted(enabled, key=class_priority)
        active_agents = sorted({
            agent_for_class(module)
            for module in enabled
            if agent_for_class(module) != "hunt"
        })
        for agent in active_agents:
            context.scheduler.state(agent).status = "running"
            await context.emit(
                EventType.AGENT_STARTED,
                agent=agent,
                phase=self.phase,
                message="{} specialist ready".format(agent),
            )

        async def log(message: str, level: str = "info"):
            await context.log(
                message,
                level,
                agent=agent_for_class(message),
                phase=self.phase,
            )

        async def progress(_phase, current, total, label):
            agent = agent_for_class(label)
            context.scheduler.state(agent).last_event = label
            await context.emit(
                "agent_progress",
                agent=agent,
                phase=self.phase,
                message=label,
                current=current,
                total=total,
                vulnerability_class=label,
            )

        async def request_event(event: dict):
            url = str(event.get("url", ""))
            if url and not context.scope.allows(url):
                await context.emit(
                    EventType.SKIPPED,
                    agent=agent_for_class(event.get("vulnerability_class", "")),
                    phase=self.phase,
                    message="Skipped out-of-scope request",
                    url=url,
                    reason="out_of_scope",
                )
                return
            agent = agent_for_class(event.get("vulnerability_class", ""))
            if event.get("type") == "throttled":
                await context.emit(
                    EventType.THROTTLED,
                    agent=agent,
                    phase=self.phase,
                    message="Rate limiter paused {:.2f}s".format(
                        float(event.get("wait_seconds", 0) or 0)
                    ),
                    **event,
                )
                return
            if event.get("type") == "url_test":
                await context.emit(
                    EventType.REQUEST_TESTED,
                    agent=agent,
                    phase=self.phase,
                    message="Testing {}".format(url),
                    **event,
                )
                return
            context.tested_urls.add(url)
            await context.emit(
                EventType.RESPONSE_RECEIVED,
                agent=agent,
                phase=self.phase,
                message="{} {} → {}".format(
                    event.get("method", "GET"),
                    url,
                    event.get("status_code", event.get("error", "no response")),
                ),
                **event,
            )

        async def finding_event(finding: dict):
            normalized = normalize_findings(
                [finding], scan_id=context.scan["id"]
            )[0]
            agent = agent_for_class(normalized.get("vuln_type", ""))
            state = context.scheduler.state(agent)
            state.findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=agent,
                phase=self.phase,
                message=normalized.get("title", "Finding candidate"),
                finding=normalized,
            )

        resources = ResourceController(
            cpu_limit_percent=int(plan.get("cpu_limit_percent", 60))
        )
        findings = await run_hunt(
            prioritize_urls(
                context.recon.get("urls", []),
                context.recon.get("live_hosts", []),
            ),
            context.recon.get("live_hosts", []),
            log,
            progress,
            enabled_classes=enabled,
            max_urls=int(plan.get("max_urls", 100)),
            concurrency_override=context.options.concurrency,
            request_timeout=context.options.timeout,
            batch_size=max(1, context.options.concurrency),
            resource_controller=resources,
            scan_level=plan.get("level", "BALANCED"),
            planner=WorkingMemory(
                step_budget=100,
                time_budget=context.options.time_budget,
            ),
            request_event_cb=request_event,
            finding_event_cb=finding_event,
            rate_limiter=context.rate_limiter,
        )
        context.raw_findings = passive_findings + normalize_findings(
            findings, scan_id=context.scan["id"]
        )
        context.scan["raw_findings"] = context.raw_findings
        for agent in active_agents:
            context.scheduler.state(agent).status = "complete"
            await context.emit(
                EventType.AGENT_COMPLETED,
                agent=agent,
                phase=self.phase,
                message="{} specialist completed".format(agent),
                findings=context.scheduler.state(agent).findings,
            )
        return context.raw_findings

    async def _passive_observations(self, context: ScanContext):
        # Imported lazily to avoid circular imports through core.agents.
        from core.agents.access_control_agent import AccessControlAgent
        from core.agents.auth_agent import AuthAgent
        from core.agents.header_agent import HeaderAgent
        from core.agents.injection_agent import InjectionAgent
        from core.agents.open_redirect_agent import OpenRedirectAgent
        from core.agents.rate_limit_agent import RateLimitAgent
        from core.agents.ssrf_agent import SSRFAgent
        from core.agents.xss_agent import XSSAgent

        await context.scheduler.run("header", lambda: HeaderAgent().execute(context))
        await context.scheduler.gather_safe([
            ("auth", lambda: AuthAgent().execute(context)),
            (
                "access-control",
                lambda: AccessControlAgent().execute(context),
            ),
            ("injection", lambda: InjectionAgent().execute(context)),
            ("xss", lambda: XSSAgent().execute(context)),
            ("rate-limit", lambda: RateLimitAgent().execute(context)),
            ("ssrf", lambda: SSRFAgent().execute(context)),
            ("open-redirect", lambda: OpenRedirectAgent().execute(context)),
        ])
        context.scan["raw_findings"] = context.raw_findings
