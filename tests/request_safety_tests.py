import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from request_safety import (
    CircuitBreaker,
    OutboundAuditLog,
    OutboundRequestGuard,
    SafeMethodPolicy,
    redact_url,
)
from scope_policy import ScopePolicy


def run_tests():
    methods = SafeMethodPolicy()
    assert methods.evaluate("GET").allowed
    assert methods.evaluate("POST", mutation=False).allowed
    assert not methods.evaluate("DELETE", mutation=True).allowed
    assert methods.evaluate(
        "DELETE", mutation=True, explicitly_approved=True
    ).allowed

    redacted = redact_url(
        "https://user:pass@example.test/api?token=secret&item=123#fragment"
    )
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "secret" not in redacted
    assert "123" not in redacted
    assert "token=" in redacted and "item=" in redacted

    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    assert breaker.allow("example.test").allowed
    breaker.failure("example.test")
    assert breaker.allow("example.test").allowed
    breaker.failure("example.test")
    assert not breaker.allow("example.test").allowed
    breaker.success("example.test")
    assert breaker.allow("example.test").allowed

    policy = ScopePolicy()
    policy.update({
        "allowed_domains": ["example.test"],
        "blocked_domains": [],
        "active_testing_enabled": True,
        "passive_only_mode": False,
        "emergency_stop": False,
        "max_requests_per_minute": 100,
        "max_total_requests": 100,
    }, persist=False)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "requests.jsonl"
        guard = OutboundRequestGuard(
            audit_log=OutboundAuditLog(path),
            circuit_breaker=CircuitBreaker(failure_threshold=2),
        )
        allowed = guard.authorize(
            policy,
            "https://example.test/search?token=secret",
            method="GET",
            action="active",
        )
        assert allowed.allowed
        guard.record_result(
            "https://example.test/search?token=secret",
            method="GET",
            action="active",
            status_code=200,
            elapsed_ms=12.3,
        )
        blocked = guard.authorize(
            policy,
            "https://evil.test/",
            method="GET",
            action="active",
        )
        assert not blocked.allowed
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        assert len(records) == 2
        assert records[0]["outcome"] == "completed"
        assert records[1]["outcome"] == "blocked_by_scope"
        assert all("secret" not in json.dumps(record) for record in records)

    print("REQUEST SAFETY TESTS: PASS")


if __name__ == "__main__":
    run_tests()
