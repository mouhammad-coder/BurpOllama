from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.agents.open_redirect_agent import OpenRedirectAgent


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
    allowed_domains = ["example.com"]

    def allows(self, url):
        return "example.com" in str(url)


class _Context:
    def __init__(self, recon, output):
        self.scan = {
            "id": "open-redirect-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(mode="passive")
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))


class OpenRedirectPassiveTests(unittest.TestCase):
    def _run(self, recon):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name)
        findings = asyncio.run(OpenRedirectAgent().run(ctx))
        return ctx, findings

    def test_redirect_external_url_is_higher_confidence_candidate(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/login?redirect=https://evil.example/path"]
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        artifact = findings[0]["evidence_artifact"]
        self.assertEqual(artifact["metadata"]["confidence"], "higher")
        self.assertEqual(artifact["metadata"]["parameter"], "redirect")
        self.assertTrue(Path(artifact["artifact_path"]).exists())

    def test_next_internal_path_is_low_confidence_candidate(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/login?next=/dashboard"]
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        self.assertEqual(findings[0]["evidence_artifact"]["metadata"]["confidence"], "low")

    def test_protocol_relative_value_is_higher_confidence_candidate(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/login?returnTo=//evil.example/path"]
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence_artifact"]["metadata"]["confidence"], "higher")
        self.assertEqual(findings[0]["parameter"], "returnTo")

    def test_generic_parameters_are_not_flagged(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/search?q=test&search=redirect&id=123"]
        })
        self.assertEqual(findings, [])

    def test_passive_mode_sends_zero_probe_requests(self):
        ctx, findings = self._run({
            "urls": ["https://example.com/login?redirect=https://evil.example/path"]
        })
        self.assertTrue(findings)
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertEqual(ctx.tested_urls, set())


if __name__ == "__main__":
    unittest.main()
