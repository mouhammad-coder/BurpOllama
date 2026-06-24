from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.agents.header_agent import HeaderAgent


class _Scheduler:
    def __init__(self):
        self.states = {}

    def state(self, name):
        self.states.setdefault(
            name,
            SimpleNamespace(findings=0, last_event="", status="pending"),
        )
        return self.states[name]

    async def checkpoint(self):
        return None


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
    def __init__(self, observation, output):
        self.scan = {
            "id": "cors-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(timeout=1.0, retries=0, concurrency=1)
        self.recon = {
            "urls": [],
            "http_observations": [observation],
        }
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))


class CorsMisconfigurationTests(unittest.TestCase):
    def _run(self, headers, request_origin="https://attacker.example"):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(
                {
                    "url": "https://example.com/api/data",
                    "method": "GET",
                    "headers": headers,
                    "request_headers": {"Origin": request_origin} if request_origin else {},
                    "status_code": 200,
                    "body": "",
                },
                temp,
            )
            findings = asyncio.run(HeaderAgent().run(ctx))
            return ctx, findings

    def test_wildcard_plus_credentials_is_confirmed(self):
        _ctx, findings = self._run({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["exploitability_status"], "confirmed")
        self.assertTrue(Path(findings[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_reflected_origin_plus_credentials_is_candidate(self):
        _ctx, findings = self._run({
            "Access-Control-Allow-Origin": "https://attacker.example",
            "Access-Control-Allow-Credentials": "true",
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        self.assertIn("https://attacker.example", findings[0]["evidence"])

    def test_null_origin_is_candidate(self):
        _ctx, findings = self._run({
            "Access-Control-Allow-Origin": "null",
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        self.assertEqual(findings[0]["evidence_artifact"]["metadata"]["acao"], "null")

    def test_wildcard_without_credentials_is_not_a_finding(self):
        _ctx, findings = self._run({
            "Access-Control-Allow-Origin": "*",
        })
        self.assertEqual(findings, [])

    def test_no_extra_requests_sent(self):
        ctx, findings = self._run({
            "Access-Control-Allow-Origin": "null",
        })
        self.assertTrue(findings)
        self.assertEqual(ctx.tested_urls, set())
        self.assertEqual(ctx.rate_limiter.calls, 0)


if __name__ == "__main__":
    unittest.main()
