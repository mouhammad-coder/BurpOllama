"""Target probing and bounded reconnaissance agent."""

from __future__ import annotations

from adaptive_scan import build_adaptive_plan, profile_target
from recon_engine import RECON_RATE_LIMITER, run_full_recon

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class ReconAgent(BaseAgent):
    name = "recon"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        profile = await profile_target(context.scan["target"], _ScopeAdapter(context))
        plan = build_adaptive_plan(profile, context.options.internal_mode)
        plan.concurrency = min(plan.concurrency, context.options.concurrency)
        plan.request_timeout = context.options.timeout
        context.scan["target_profile"] = profile.to_dict()
        context.scan["adaptive_plan"] = plan.to_dict()

        async def log(message: str, level: str = "info"):
            await context.log(message, level, agent=self.name, phase=self.phase)

        limiter_token = RECON_RATE_LIMITER.set(context.rate_limiter)
        try:
            recon = await run_full_recon(
                context.scan["target"],
                log,
                adaptive_plan=plan.to_dict(),
                use_external_tools=False,
            )
        finally:
            RECON_RATE_LIMITER.reset(limiter_token)
        allowed, skipped = context.scope.filter(recon.get("urls", []))
        recon["urls"] = list(dict.fromkeys(allowed or [context.scan["target"]]))
        recon["skipped_out_of_scope"] = skipped
        context.recon = recon
        context.scan["recon"] = recon
        for url in recon["urls"]:
            await context.emit(
                EventType.URL_DISCOVERED,
                agent=self.name,
                phase=self.phase,
                message="Discovered {}".format(url),
                url=url,
            )
        for url in skipped:
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped out-of-scope URL",
                url=url,
                reason="out_of_scope",
            )
        return recon


class _ScopeAdapter:
    def __init__(self, context: ScanContext):
        self.context = context

    def validate_target(self, target: str, action: str = "scan"):
        return (
            (True, "Allowed by CLI scope")
            if self.context.scope.allows(target)
            else (False, "Outside CLI scope")
        )

    def record_request(self, target: str, action: str = "scan"):
        if not self.context.scope.allows(target):
            return False, "Outside CLI scope"
        # The adaptive profiler is intentionally tiny; the main hunt path uses
        # the shared asynchronous limiter.
        return True, "Allowed by CLI scope"
