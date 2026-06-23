"""Bounded cooperative scheduler for specialist scan agents."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


class ScanCancelled(Exception):
    """Raised when the user requests a clean scan shutdown."""


@dataclass
class AgentState:
    name: str
    status: str = "pending"
    tasks_completed: int = 0
    findings: int = 0
    last_event: str = ""


class Scheduler:
    def __init__(self, concurrency: int = 5):
        self.concurrency = max(1, min(int(concurrency), 20))
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._stop = asyncio.Event()
        self.states: dict[str, AgentState] = {}
        self.tasks: set[asyncio.Task] = set()

    def state(self, agent: str) -> AgentState:
        return self.states.setdefault(agent, AgentState(agent))

    def request_stop(self) -> None:
        self._stop.set()
        for task in list(self.tasks):
            if not task.done():
                task.cancel()

    def should_continue(self) -> bool:
        return not self._stop.is_set()

    async def checkpoint(self) -> None:
        if self._stop.is_set():
            raise ScanCancelled("Scan interrupted by user")
        await asyncio.sleep(0)

    async def run(
        self,
        agent: str,
        operation: Callable[[], Awaitable[Any]],
    ) -> Any:
        await self.checkpoint()
        state = self.state(agent)
        state.status = "running"
        async with self._semaphore:
            await self.checkpoint()
            task = asyncio.current_task()
            if task:
                self.tasks.add(task)
            try:
                result = await operation()
                state.status = "complete"
                state.tasks_completed += 1
                return result
            except asyncio.CancelledError as exc:
                state.status = "stopped"
                raise ScanCancelled("Scan interrupted by user") from exc
            except Exception:
                state.status = "error"
                raise
            finally:
                if task:
                    self.tasks.discard(task)

    async def gather_safe(
        self,
        jobs: list[tuple[str, Callable[[], Awaitable[Any]]]],
    ) -> list[Any]:
        async def execute(name, operation):
            return await self.run(name, operation)

        return await asyncio.gather(
            *(execute(name, operation) for name, operation in jobs)
        )

    def snapshot(self) -> dict[str, dict]:
        return {
            name: {
                "name": state.name,
                "status": state.status,
                "tasks_completed": state.tasks_completed,
                "findings": state.findings,
                "last_event": state.last_event,
            }
            for name, state in self.states.items()
        }
