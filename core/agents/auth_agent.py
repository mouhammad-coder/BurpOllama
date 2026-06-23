"""Non-destructive authentication surface observations."""

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class AuthAgent(BaseAgent):
    name = "auth"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        auth_urls = [
            url for url in context.recon.get("urls", [])
            if any(term in url.lower() for term in (
                "login", "signin", "oauth", "session", "password", "reset"
            ))
        ]
        await context.emit(
            EventType.SKIPPED if not auth_urls else EventType.LOG,
            agent=self.name,
            phase=self.phase,
            message=(
                "{} authentication endpoint(s) observed; no brute force attempted".format(
                    len(auth_urls)
                )
                if auth_urls
                else "No authentication endpoints observed"
            ),
            level="info",
        )
        return auth_urls
