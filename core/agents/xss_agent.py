"""Mode-gated XSS specialist."""

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class XSSAgent(BaseAgent):
    name = "xss"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        js_findings = context.recon.get("js_findings", [])
        await context.emit(
            EventType.LOG,
            agent=self.name,
            phase=self.phase,
            message=(
                "{} passive JavaScript observation(s); active payloads skipped".format(
                    len(js_findings)
                )
            ),
            level="info",
        )
        return []
