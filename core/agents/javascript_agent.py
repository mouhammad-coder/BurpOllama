"""JavaScript endpoint and hidden-route intelligence agent."""

from recon_intelligence import advanced_recon_intelligence

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class JavaScriptAgent(BaseAgent):
    name = "javascript"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        live_hosts = [
            item.get("url", "")
            for item in context.recon.get("live_hosts", [])
            if isinstance(item, dict)
        ]
        intelligence = await advanced_recon_intelligence(
            context.scan["target"],
            context.recon.get("urls", []),
            context.recon.get("js_contents", {}),
            live_hosts,
            context.recon.get("tech_stack", []),
        )
        context.recon["intelligence"] = intelligence
        for url in intelligence.get("hidden_endpoints", [])[:100]:
            if context.scope.allows(url):
                await context.emit(
                    EventType.URL_DISCOVERED,
                    agent=self.name,
                    phase=self.phase,
                    message="JavaScript endpoint {}".format(url),
                    url=url,
                    source="javascript",
                )
        return intelligence
