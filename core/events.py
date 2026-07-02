"""Typed in-process events shared by the CLI and optional web transport."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    PHASE_STARTED = "phase_started"
    PHASE_COMPLETED = "phase_completed"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    URL_DISCOVERED = "url_discovered"
    REQUEST_TESTED = "request_tested"
    RESPONSE_RECEIVED = "response_received"
    FINDING_CANDIDATE = "finding_candidate"
    FINDING_CONFIRMED = "finding_confirmed"
    AI_NOTE = "ai_note"
    AI_HYPOTHESIS = "ai_hypothesis"
    AI_STRATEGY = "ai_strategy"
    AI_TRIAGE = "ai_triage"
    SKIPPED = "skipped"
    THROTTLED = "throttled"
    ERROR = "error"
    FINDINGS_PREPARED = "findings_prepared"
    LOG = "log"
    SCAN_COMPLETED = "scan_completed"
    SCAN_INTERRUPTED = "scan_interrupted"


@dataclass(slots=True)
class ScanEvent:
    type: str
    scan_id: str
    agent: str = ""
    phase: str = ""
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


EventCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class ScanEventBus:
    def __init__(self):
        self._subscribers: set[EventCallback] = set()

    def subscribe(self, callback: EventCallback) -> None:
        self._subscribers.add(callback)

    def unsubscribe(self, callback: EventCallback) -> None:
        self._subscribers.discard(callback)

    async def emit(self, event: ScanEvent | dict[str, Any]) -> None:
        payload = event.to_dict() if isinstance(event, ScanEvent) else dict(event)
        for callback in list(self._subscribers):
            try:
                result = callback(dict(payload))
                if inspect.isawaitable(result):
                    await result
            except Exception:
                # Rendering and optional transports cannot stop the scanner.
                continue

    @asynccontextmanager
    async def listening(self, callback: EventCallback):
        self.subscribe(callback)
        try:
            yield
        finally:
            self.unsubscribe(callback)


event_bus = ScanEventBus()
