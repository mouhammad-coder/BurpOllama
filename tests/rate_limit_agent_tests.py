from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.rate_limit_agent import RateLimitAgent
from core.ratelimit import RateLimiter


class _Scheduler:
    def __init__(self):
        self.states = {}

    def state(self, name):
        self.states.setdefault(
            name,
            SimpleNamespace(findings=0, last_event="", status="pending"),
        )
        return self.states[name]


class _RateLimiter:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1
        return 0


class _Scope:
    def allows(self, url):
        return "example.com" in str(url)


class _Context:
    def __init__(self, recon, output, mode="passive", goal=""):
        self.scan = {
            "id": "rate-limit-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(mode=mode, timeout=1.0, goal=goal)
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))

    async def observe_response(self, *_args, **_kwargs):
        return None


class GlobalRateLimiterTests(unittest.TestCase):
    def test_enters_conservative_mode_on_429(self):
        limiter = RateLimiter(4.0)
        changed = limiter.record_response(429)
        snapshot = limiter.snapshot()
        self.assertTrue(changed)
        self.assertTrue(snapshot["conservative_mode"])
        self.assertEqual(snapshot["requests_per_second"], 2.0)
        self.assertEqual(snapshot["block_events"], 1)


class _Response:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _Client:
    calls = 0
    statuses = []
    headers = {}

    def __init__(self, *args, **kwargs):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, _url):
        type(self).calls += 1
        index = min(type(self).calls - 1, len(type(self).statuses) - 1)
        return _Response(type(self).statuses[index], dict(type(self).headers))


class RateLimitAgentTests(unittest.TestCase):
    def _run(self, recon, mode="passive", goal=""):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name, mode=mode, goal=goal)
        findings = asyncio.run(RateLimitAgent().run(ctx))
        return ctx, findings

    def test_login_endpoint_without_rate_limit_headers_is_candidate(self):
        _ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/login",
                "method": "GET",
                "headers": {"content-type": "text/html"},
                "status_code": 200,
            }]
        })
        self.assertTrue(findings)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        self.assertTrue(Path(findings[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_login_endpoint_with_rate_limit_header_not_flagged(self):
        _ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/login",
                "headers": {"X-RateLimit-Limit": "10"},
                "status_code": 200,
            }]
        })
        self.assertEqual(findings, [])

    def test_generic_endpoint_without_headers_not_flagged(self):
        _ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/about",
                "headers": {},
                "status_code": 200,
            }]
        })
        self.assertEqual(findings, [])

    def test_bounty_probe_five_200_responses_higher_confidence_artifact(self):
        _Client.calls = 0
        _Client.statuses = [200, 200, 200, 200, 200]
        _Client.headers = {}
        with patch("core.agents.rate_limit_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "status_code": 200,
                }]
            }, mode="bounty")
        self.assertEqual(_Client.calls, 5)
        self.assertEqual(ctx.rate_limiter.calls, 5)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["exploitability_status"], "confirmed")
        self.assertGreaterEqual(findings[0]["confidence"], 80)
        artifact = findings[0]["evidence_artifact"]
        self.assertEqual(len(artifact["metadata"]["responses"]), 5)

    def test_bounty_probe_429_received_false_positive(self):
        _Client.calls = 0
        _Client.statuses = [200, 200, 429, 429, 429]
        _Client.headers = {}
        with patch("core.agents.rate_limit_agent.httpx.AsyncClient", _Client):
            _ctx, findings = self._run({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "status_code": 200,
                }]
            }, mode="bounty")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["exploitability_status"], "false_positive")

    def test_passive_mode_sends_no_probe_requests(self):
        _Client.calls = 0
        _Client.statuses = [200, 200, 200, 200, 200]
        with patch("core.agents.rate_limit_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "status_code": 200,
                }]
            })
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, 0)
        self.assertEqual(ctx.rate_limiter.calls, 0)

    def test_probe_hard_stops_at_five_requests(self):
        _Client.calls = 0
        _Client.statuses = [200] * 10
        _Client.headers = {}
        with patch("core.agents.rate_limit_agent.httpx.AsyncClient", _Client):
            _ctx, findings = self._run({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "status_code": 200,
                }]
            }, mode="bounty")
        self.assertEqual(_Client.calls, 5)
        self.assertEqual(len(findings[0]["evidence_artifact"]["metadata"]["responses"]), 5)

    def test_bounty_hunt_goal_is_observation_only(self):
        _Client.calls = 0
        _Client.statuses = [200] * 5
        _Client.headers = {}
        with patch("core.agents.rate_limit_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "status_code": 200,
                }]
            }, mode="bounty", goal="bounty-hunt")
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, 0)
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")


if __name__ == "__main__":
    unittest.main()
