"""Mode-gated injection specialist."""

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class InjectionAgent(BaseAgent):
    name = "injection"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        await context.emit(
            EventType.SKIPPED,
            agent=self.name,
            phase=self.phase,
            message="Skipped active SQLi/SSTI/command payloads in passive mode",
            reason="passive_mode",
        )
        return []
