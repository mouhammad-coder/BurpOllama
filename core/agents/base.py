"""Agent primitives and shared scan context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.events import EventType, ScanEvent, ScanEventBus
from core.ratelimit import RateLimiter
from core.scheduler import Scheduler
from core.scope import ScanScope
from core.storage import ScanStore


@dataclass
class ScanContext:
    scan: dict[str, Any]
    options: Any
    events: ScanEventBus
    scheduler: Scheduler
    rate_limiter: RateLimiter
    scope: ScanScope
    store: ScanStore
    recon: dict[str, Any] = field(default_factory=dict)
    raw_findings: list[dict] = field(default_factory=list)
    triaged_findings: list[dict] = field(default_factory=list)
    analysis: dict[str, Any] = field(default_factory=dict)
    report_paths: dict[str, str] = field(default_factory=dict)
    tested_urls: set[str] = field(default_factory=set)
    blackboard: list[dict[str, Any]] = field(default_factory=list)

    async def emit(
        self,
        event_type: EventType | str,
        *,
        agent: str = "",
        phase: str = "",
        message: str = "",
        **data,
    ) -> None:
        event = ScanEvent(
            type=event_type.value if isinstance(event_type, EventType) else event_type,
            scan_id=self.scan["id"],
            agent=agent,
            phase=phase,
            message=message,
            data=data,
        )
        if agent:
            state = self.scheduler.state(agent)
            state.last_event = message
        if (
            event.type
            in {
                EventType.AI_NOTE.value,
                EventType.AI_HYPOTHESIS.value,
                EventType.AI_STRATEGY.value,
            }
        ):
            entry = {
                "type": event.type,
                "agent": agent,
                "phase": phase,
                "message": message,
                "data": dict(data),
                "timestamp": event.timestamp,
            }
            self.blackboard.append(entry)
            self.scan.setdefault("blackboard", []).append(entry)
        await self.events.emit(event)

    async def log(
        self,
        message: str,
        level: str = "info",
        *,
        agent: str = "",
        phase: str = "",
    ) -> None:
        self.scan.setdefault("logs", []).append(
            {"ts": "", "msg": message, "level": level, "agent": agent}
        )
        await self.emit(
            EventType.LOG,
            agent=agent,
            phase=phase,
            message=message,
            level=level,
        )


class BaseAgent:
    name = "agent"
    phase = ""

    async def execute(self, context: ScanContext):
        await context.emit(
            EventType.AGENT_STARTED,
            agent=self.name,
            phase=self.phase,
            message="{} started".format(self.name),
        )
        try:
            result = await self.run(context)
            await context.emit(
                EventType.AGENT_COMPLETED,
                agent=self.name,
                phase=self.phase,
                message="{} completed".format(self.name),
                findings=context.scheduler.state(self.name).findings,
            )
            return result
        except Exception as exc:
            await context.emit(
                EventType.ERROR,
                agent=self.name,
                phase=self.phase,
                message=str(exc),
            )
            raise

    async def run(self, context: ScanContext):
        raise NotImplementedError
