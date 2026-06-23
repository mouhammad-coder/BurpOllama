"""Safe mode-gated rate-limit specialist."""

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class RateLimitAgent(BaseAgent):
    name = "rate-limit"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        await context.emit(
            EventType.SKIPPED,
            agent=self.name,
            phase=self.phase,
            message="Skipped active rate-limit test in passive mode",
            reason="passive_mode",
        )
        return []
