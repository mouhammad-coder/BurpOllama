from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.ssrf_agent import SSRFAgent


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
    def __init__(self, recon, output, mode="passive", oob_server=""):
        self.scan = {
            "id": "ssrf-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(
            mode=mode,
            timeout=1.0,
            oob_server=oob_server,
        )
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))


class _Response:
    status_code = 200
    headers = {"content-type": "text/plain"}


class _Client:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        self.calls.append(url)
        return _Response()


class SSRFCandidateDetectionTests(unittest.TestCase):
    def _run(self, recon, mode="passive", oob_server=""):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name, mode=mode, oob_server=oob_server)
        findings = asyncio.run(SSRFAgent().run(ctx))
        return ctx, findings

    def test_url_parameter_detected_as_ssrf_candidate(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/fetch?url=https://cdn.example.com/a.png"]
        })
        self.assertTrue(findings)
        self.assertEqual(findings[0]["vuln_type"], "SSRF Candidate")
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        artifact = findings[0]["evidence_artifact"]
        self.assertEqual(artifact["metadata"]["parameter"], "url")
        self.assertTrue(Path(artifact["artifact_path"]).exists())

    def test_webhook_parameter_detected(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/integrations?webhook=https://hooks.example.net"]
        })
        self.assertTrue(any(f.get("parameter") == "webhook" for f in findings))

    def test_generic_parameters_are_not_flagged(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/search?q=ssrf&search=url"]
        })
        self.assertEqual(findings, [])

    def test_metadata_ip_value_needs_manual_validation(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/fetch?url=http://169.254.169.254/latest/meta-data"]
        })
        self.assertTrue(findings)
        self.assertEqual(findings[0]["exploitability_status"], "needs_manual_validation")
        self.assertTrue(findings[0]["evidence_artifact"]["metadata"]["metadata_endpoint_value"])

    def test_oob_probe_disabled_without_oob_server(self):
        _Client.calls = []
        with patch("core.agents.ssrf_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({
                "urls": ["https://example.com/fetch?url=https://target.example"]
            }, mode="bounty")
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, [])
        self.assertEqual(ctx.rate_limiter.calls, 0)

    def test_oob_probe_produces_confirmed_artifact_when_callback_mocked(self):
        _Client.calls = []
        recon = {
            "urls": ["https://example.com/fetch?url=https://target.example"]
        }
        with patch("core.agents.ssrf_agent.httpx.AsyncClient", _Client), patch.object(
            SSRFAgent,
            "_wait_for_oob_callback",
            return_value=True,
        ):
            ctx, findings = self._run(
                recon,
                mode="bounty",
                oob_server="https://oob.example/callback",
            )
        self.assertEqual(len(_Client.calls), 1)
        self.assertIn("url=https%3A%2F%2Foob.example%2Fcallback", _Client.calls[0])
        self.assertEqual(ctx.rate_limiter.calls, 1)
        self.assertEqual(findings[0]["exploitability_status"], "confirmed")
        artifact = findings[0]["evidence_artifact"]
        self.assertTrue(Path(artifact["artifact_path"]).exists())
        self.assertTrue(artifact["metadata"]["callback_received"])

    def test_passive_mode_sends_zero_probe_requests(self):
        _Client.calls = []
        with patch("core.agents.ssrf_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({
                "urls": ["https://example.com/fetch?url=https://target.example"]
            }, mode="passive", oob_server="https://oob.example/callback")
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, [])
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertEqual(ctx.tested_urls, set())


if __name__ == "__main__":
    unittest.main()
