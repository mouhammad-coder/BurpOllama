"""Crawler result agent (recon engine performs the bounded crawl)."""

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class CrawlerAgent(BaseAgent):
    name = "crawler"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        urls = context.recon.get("urls", [])
        for index, url in enumerate(urls, start=1):
            await context.emit(
                EventType.URL_DISCOVERED,
                agent=self.name,
                phase=self.phase,
                message="Crawled {}".format(url),
                url=url,
                current=index,
                total=len(urls),
            )
        return urls
