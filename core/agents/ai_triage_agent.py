"""Optional redacted AI triage agent."""

from ai_provider import ai_router
from triage_gate import batch_triage, run_deep_analysis

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class AITriageAgent(BaseAgent):
    name = "ai-triage"
    phase = "ai_triage"

    async def run(self, context: ScanContext):
        availability = await ai_router.availability()
        if (
            not context.scan.get("ai", {}).get("agents_enabled")
            or not availability.get("triage_capable")
        ):
            for finding in context.raw_findings:
                finding.update({
                    "verdict": "NEEDS_MANUAL_REVIEW",
                    "triaged": False,
                    "ai_summary": "AI disabled — manual review only",
                })
            context.triaged_findings = list(context.raw_findings)
            context.scan["triaged_findings"] = context.triaged_findings
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="AI disabled — manual review only",
                reason="no_provider",
            )
            return context.triaged_findings

        async def log(message: str, level: str = "info"):
            await context.log(message, level, agent=self.name, phase=self.phase)

        triaged, stats = await batch_triage(
            context.raw_findings,
            context.options.api_key,
            log,
        )
        context.triaged_findings = triaged
        for finding in triaged:
            triage = finding.get("triage", {})
            # Never persist or display hidden reasoning traces.
            triage.pop("chain_of_thought", None)
            summary = (
                triage.get("impact_statement")
                or triage.get("kill_reason")
                or "Manual validation is recommended."
            )
            finding["ai_recommendation"] = {
                "confidence": finding.get("confidence", 0),
                "reasoning_summary": summary,
                "impact_summary": (
                    finding.get("business_impact")
                    or finding.get("technical_impact")
                    or summary
                ),
                "false_positive_risk": finding.get(
                    "false_positive_risk", "unknown"
                ),
                "next_manual_validation_steps": finding.get(
                    "safe_manual_validation_steps"
                ) or finding.get("reproduction_steps") or [
                    "Review the captured request and response.",
                    "Reproduce within the authorized program scope.",
                    "Collect stronger evidence before submission.",
                ],
                "bounty_wording_suggestion": (
                    "{} at {}: {}".format(
                        finding.get("title") or finding.get("vuln_type"),
                        finding.get("url", ""),
                        summary,
                    )
                ),
            }
            await context.emit(
                EventType.AI_TRIAGE,
                agent=self.name,
                phase=self.phase,
                message="Reviewed {}".format(
                    finding.get("title") or finding.get("vuln_type")
                ),
                finding_id=finding.get("id"),
                recommendation=finding["ai_recommendation"],
            )
        context.scan["triaged_findings"] = triaged
        context.scan["ai_triage_stats"] = stats
        context.analysis.update(
            await run_deep_analysis(
                triaged,
                context.recon,
                api_key=context.options.api_key,
            )
        )
        await context.emit(
            EventType.AI_TRIAGE,
            agent=self.name,
            phase=self.phase,
            message="AI reviewed {} finding(s)".format(len(triaged)),
            provider=availability.get("active_provider"),
            model=availability.get("active_model"),
            stats=stats,
        )
        return triaged
