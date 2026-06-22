"""Outbound request safety, audit, and circuit-breaker primitives.

The module is dependency-light so scanners can use it without importing the
FastAPI application or database layer. Audit records never include request or
response bodies, credentials, cookies, or raw query-string values.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SENSITIVE_QUERY_NAMES = frozenset({
    "access_token", "api_key", "apikey", "auth", "authorization", "code",
    "cookie", "key", "password", "secret", "session", "signature", "token",
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_url(url: str) -> str:
    """Remove user-info and query values while retaining useful routing data."""
    try:
        parsed = urlsplit(str(url or ""))
        hostname = parsed.hostname or ""
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = "[{}]".format(hostname)
        if parsed.port:
            netloc += ":{}".format(parsed.port)
        query = []
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            replacement = "<redacted>" if name.lower() in SENSITIVE_QUERY_NAMES else "<value>"
            query.append((name, replacement if value else ""))
        return urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            urlencode(query),
            "",
        ))
    except Exception:
        return "<invalid-url>"


@dataclass(frozen=True)
class RequestDecision:
    allowed: bool
    outcome: str
    reason: str


class SafeMethodPolicy:
    """Require explicit authorization for requests expected to change state."""

    def evaluate(
        self,
        method: str,
        *,
        mutation: bool = False,
        explicitly_approved: bool = False,
    ) -> RequestDecision:
        normalized = str(method or "GET").upper()
        if normalized in SAFE_METHODS:
            return RequestDecision(True, "allow", "Read-only HTTP method.")
        if not mutation:
            return RequestDecision(
                True,
                "allow",
                "Non-persistent active probe; scanner must verify no state change.",
            )
        if explicitly_approved:
            return RequestDecision(
                True,
                "allow",
                "State-changing request explicitly authorized.",
            )
        return RequestDecision(
            False,
            "require_approval",
            "State-changing HTTP method requires explicit mutation authorization.",
        )


class CircuitBreaker:
    """Small per-host circuit breaker for repeated network/server failures."""

    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 30.0):
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_seconds = max(0.1, float(cooldown_seconds))
        self._state: dict[str, dict[str, float | int]] = {}
        self._lock = threading.Lock()

    def allow(self, host: str) -> RequestDecision:
        key = str(host or "").lower()
        now = time.monotonic()
        with self._lock:
            state = self._state.get(key)
            if not state:
                return RequestDecision(True, "allow", "Circuit closed.")
            opened_at = float(state.get("opened_at", 0.0))
            if opened_at and now - opened_at < self.cooldown_seconds:
                return RequestDecision(
                    False,
                    "circuit_open",
                    "Host circuit is temporarily open after repeated failures.",
                )
            if opened_at:
                state["opened_at"] = 0.0
                state["failures"] = 0
                return RequestDecision(True, "allow", "Circuit cooldown elapsed.")
        return RequestDecision(True, "allow", "Circuit closed.")

    def success(self, host: str) -> None:
        with self._lock:
            self._state.pop(str(host or "").lower(), None)

    def failure(self, host: str) -> None:
        key = str(host or "").lower()
        with self._lock:
            state = self._state.setdefault(key, {"failures": 0, "opened_at": 0.0})
            state["failures"] = int(state["failures"]) + 1
            if int(state["failures"]) >= self.failure_threshold:
                state["opened_at"] = time.monotonic()

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


class OutboundAuditLog:
    """Append-only JSONL audit log with basic size rotation."""

    def __init__(self, path: str | Path | None = None, max_bytes: int = 10_000_000):
        default = Path(os.path.expanduser("~/.burpollama/outbound_requests.jsonl"))
        self.path = Path(path or os.getenv("BURPOLLAMA_REQUEST_AUDIT_PATH", str(default)))
        self.max_bytes = max(1024, int(max_bytes))
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        record = {"timestamp": _utc_now(), **event}
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                    backup = self.path.with_suffix(self.path.suffix + ".1")
                    if backup.exists():
                        backup.unlink()
                    self.path.replace(backup)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
        except OSError:
            # Auditing must not crash a scan when the disk is read-only or full.
            return


class OutboundRequestGuard:
    def __init__(
        self,
        *,
        audit_log: OutboundAuditLog | None = None,
        method_policy: SafeMethodPolicy | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.audit_log = audit_log or OutboundAuditLog()
        self.method_policy = method_policy or SafeMethodPolicy()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    @staticmethod
    def _host(url: str) -> str:
        try:
            return (urlsplit(url).hostname or "").lower()
        except Exception:
            return ""

    def authorize(
        self,
        policy,
        url: str,
        *,
        method: str,
        action: str,
        mutation: bool = False,
        explicitly_approved: bool = False,
    ) -> RequestDecision:
        normalized = str(method or "GET").upper()
        method_decision = self.method_policy.evaluate(
            normalized,
            mutation=mutation,
            explicitly_approved=explicitly_approved,
        )
        if not method_decision.allowed:
            self._audit(url, normalized, action, method_decision)
            return method_decision

        allowed, reason = policy.record_request(url, action=action)
        if not allowed:
            decision = RequestDecision(False, "blocked_by_scope", reason)
            self._audit(url, normalized, action, decision)
            return decision

        circuit_decision = self.circuit_breaker.allow(self._host(url))
        if not circuit_decision.allowed:
            self._audit(url, normalized, action, circuit_decision)
            return circuit_decision
        return RequestDecision(True, "allow", "Request authorized.")

    def record_result(
        self,
        url: str,
        *,
        method: str,
        action: str,
        status_code: int | None = None,
        elapsed_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        host = self._host(url)
        failed = error is not None or (
            status_code is not None and int(status_code) >= 500
        )
        if failed:
            self.circuit_breaker.failure(host)
        else:
            self.circuit_breaker.success(host)
        decision = RequestDecision(
            True,
            "network_error" if error else "completed",
            str(error or "HTTP request completed."),
        )
        self._audit(
            url,
            str(method or "GET").upper(),
            action,
            decision,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
        )

    def _audit(
        self,
        url: str,
        method: str,
        action: str,
        decision: RequestDecision,
        *,
        status_code: int | None = None,
        elapsed_ms: float | None = None,
    ) -> None:
        event = {
            "event": "outbound_http_request",
            "method": method,
            "url": redact_url(url),
            "host": self._host(url),
            "action": action,
            **asdict(decision),
        }
        if status_code is not None:
            event["status_code"] = int(status_code)
        if elapsed_ms is not None:
            event["elapsed_ms"] = round(float(elapsed_ms), 2)
        self.audit_log.append(event)


outbound_guard = OutboundRequestGuard()
