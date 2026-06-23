"""Budgeted, loop-aware working memory for autonomous scan planning."""

from __future__ import annotations

import time
from collections import Counter
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class PlannerState(str, Enum):
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETE = "COMPLETE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


CLASS_RISK = {
    "SQL Injection": 100,
    "OS Command Injection": 98,
    "Auth Bypass": 96,
    "IDOR": 95,
    "GraphQL Authorization": 94,
    "SSRF": 92,
    "Path Traversal and LFI": 90,
    "Stored XSS": 88,
    "Blind XSS": 87,
    "XSS": 85,
    "Business Logic": 84,
    "Deep Business Logic Hunting": 84,
    "OAuth Flow Tester": 82,
    "JWT": 80,
    "Mass Assignment Testing": 78,
    "NoSQL Injection": 76,
    "Prototype Pollution Testing": 74,
    "Request Smuggling": 72,
    "Sensitive Paths": 70,
    "API Version Testing": 68,
    "CORS": 60,
    "Session Security": 58,
    "Security Headers": 40,
    "Clickjacking": 35,
}


class WorkingMemory:
    def __init__(
        self,
        step_budget: int = 100,
        time_budget: int = 1800,
    ):
        self.completed_steps: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.next_priorities: list[dict[str, Any]] = []
        self.loop_detection: dict[str, int] = {}
        self.step_budget = max(1, int(step_budget))
        self.time_budget = max(1, int(time_budget))
        self.started_at = time.monotonic()
        self.state = PlannerState.PLANNING

    @classmethod
    def from_dict(cls, value: dict | None) -> "WorkingMemory":
        data = value if isinstance(value, dict) else {}
        memory = cls(
            step_budget=int(data.get("step_budget", 100) or 100),
            time_budget=int(data.get("time_budget", 1800) or 1800),
        )
        memory.completed_steps = [
            dict(item)
            for item in data.get("completed_steps", [])
            if isinstance(item, dict)
        ]
        memory.observations = [
            dict(item)
            for item in data.get("observations", [])
            if isinstance(item, dict)
        ]
        memory.next_priorities = [
            dict(item)
            for item in data.get("next_priorities", [])
            if isinstance(item, dict)
        ]
        memory.loop_detection = {
            str(name): max(0, int(count))
            for name, count in (data.get("loop_detection", {}) or {}).items()
        }
        elapsed = max(0.0, float(data.get("elapsed_seconds", 0) or 0))
        memory.started_at = time.monotonic() - elapsed
        try:
            memory.state = PlannerState(
                str(data.get("state", PlannerState.PLANNING.value))
            )
        except ValueError:
            memory.state = PlannerState.PLANNING
        return memory

    def record_step(
        self,
        step_name: str,
        outcome: str,
        findings_count: int,
    ) -> None:
        name = str(step_name or "unnamed step").strip()
        entry = {
            "step": name,
            "outcome": str(outcome or "completed"),
            "findings_count": max(0, int(findings_count or 0)),
            "elapsed_seconds": round(time.monotonic() - self.started_at, 2),
        }
        self.completed_steps.append(entry)
        self.loop_detection[name] = self.loop_detection.get(name, 0) + 1
        if entry["findings_count"]:
            self.observations.append({
                "step": name,
                "observation": "{} finding(s) produced".format(
                    entry["findings_count"]
                ),
            })
        self.state = PlannerState.RUNNING
        self.should_continue()

    def is_loop_detected(self) -> bool:
        return any(count >= 3 for count in self.loop_detection.values())

    def _url_hints(self, available_urls: list[str]) -> set[str]:
        hints = set()
        joined = " ".join(
            (urlparse(str(url)).path + " " + urlparse(str(url)).query).lower()
            for url in (available_urls or [])[:500]
        )
        if any(term in joined for term in ("login", "oauth", "auth", "session")):
            hints.update({"Auth Bypass", "OAuth Flow Tester", "Session Security", "JWT"})
        if any(term in joined for term in ("graphql", "graphiql")):
            hints.update({"GraphQL Authorization", "GraphQL"})
        if any(term in joined for term in ("api", "user", "account", "order", "invoice")):
            hints.update({"IDOR", "Mass Assignment Testing", "Business Logic"})
        if any(term in joined for term in ("search", "query", "filter", "id=")):
            hints.update({"SQL Injection", "XSS", "NoSQL Injection"})
        if any(term in joined for term in ("url=", "callback", "webhook", "fetch")):
            hints.add("SSRF")
        return hints

    def risk_score(self, class_name: str, available_urls: list[str]) -> int:
        score = CLASS_RISK.get(class_name, 50)
        if class_name in self._url_hints(available_urls):
            score += 15
        return min(120, score)

    def get_next_priority(
        self,
        available_urls: list[str],
        completed_classes: list[str],
    ) -> str:
        completed = set(completed_classes or [])
        candidates = [
            name for name in CLASS_RISK
            if name not in completed
        ]
        if not candidates:
            self.next_priorities = []
            return ""
        ranked = sorted(
            candidates,
            key=lambda name: (-self.risk_score(name, available_urls), name),
        )
        self.next_priorities = [
            {"class": name, "risk_score": self.risk_score(name, available_urls)}
            for name in ranked[:10]
        ]
        return ranked[0]

    def prioritize_classes(
        self,
        classes: list[tuple[str, Any]],
        available_urls: list[str],
    ) -> list[tuple[str, Any]]:
        baseline_order = {
            "Security Headers": 0,
            "Sensitive Paths": 0,
            "CORS": 1,
            "Open Redirect": 2,
        }
        first = self.get_next_priority(
            available_urls,
            [entry["step"] for entry in self.completed_steps],
        )
        return sorted(
            classes,
            key=lambda item: (
                baseline_order.get(item[0], 3),
                0 if item[0] == first else 1,
                -self.risk_score(item[0], available_urls),
                item[0],
            ),
        )

    def summarize_progress(self) -> str:
        elapsed = int(time.monotonic() - self.started_at)
        findings = sum(
            int(step.get("findings_count", 0))
            for step in self.completed_steps
        )
        return (
            "{} of {} steps completed in {}s; {} finding(s) observed. "
            "State: {}{}"
        ).format(
            len(self.completed_steps),
            self.step_budget,
            elapsed,
            findings,
            self.state.value,
            "; repeated-action loop detected" if self.is_loop_detected() else "",
        )

    def should_continue(self) -> bool:
        elapsed = time.monotonic() - self.started_at
        if (
            len(self.completed_steps) >= self.step_budget
            or elapsed >= self.time_budget
            or self.is_loop_detected()
        ):
            self.state = PlannerState.BUDGET_EXCEEDED
            return False
        if self.state == PlannerState.PLANNING:
            self.state = PlannerState.RUNNING
        return True

    def complete(self) -> None:
        if self.state != PlannerState.BUDGET_EXCEEDED:
            self.state = PlannerState.COMPLETE

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "completed_steps": list(self.completed_steps),
            "observations": list(self.observations),
            "next_priorities": list(self.next_priorities),
            "loop_detection": dict(self.loop_detection),
            "loop_detected": self.is_loop_detected(),
            "step_budget": self.step_budget,
            "time_budget": self.time_budget,
            "elapsed_seconds": round(time.monotonic() - self.started_at, 2),
            "should_continue": self.should_continue(),
            "summary": self.summarize_progress(),
        }
