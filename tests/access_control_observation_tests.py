from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.access_control_agent import AccessControlAgent


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
    def __init__(self, recon, output):
        self.scan = {
            "id": "access-control-test",
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


class AccessControlObservationTests(unittest.TestCase):
    def _run(self, recon):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name)
        findings = asyncio.run(AccessControlAgent().run(ctx))
        return ctx, findings

    def test_numeric_id_in_path_detected_correctly(self):
        _ctx, findings = self._run({"urls": ["https://example.com/api/users/1234"]})
        idor = [f for f in findings if f.get("vuln_type") == "IDOR Candidate"]
        self.assertTrue(idor)
        artifact = idor[0]["evidence_artifact"]
        self.assertEqual(artifact["metadata"]["id_type"], "numeric")
        self.assertTrue(Path(artifact["artifact_path"]).exists())

    def test_uuid_in_path_detected_correctly(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        _ctx, findings = self._run({"urls": ["https://example.com/document/" + uuid]})
        self.assertTrue(any(
            f.get("evidence_artifact", {}).get("metadata", {}).get("id_type") == "uuid"
            for f in findings
        ))

    def test_auth_coverage_gap_flagged_for_same_endpoint(self):
        _ctx, findings = self._run({
            "http_observations": [
                {
                    "url": "https://example.com/api/users/me",
                    "method": "GET",
                    "headers": {"Authorization": "Bearer secret"},
                },
                {
                    "url": "https://example.com/api/users/me",
                    "method": "GET",
                    "headers": {},
                },
            ]
        })
        gaps = [
            f for f in findings
            if f.get("vuln_type") == "Access Control Auth Coverage Gap"
        ]
        self.assertTrue(gaps)
        self.assertEqual(gaps[0]["exploitability_status"], "confirmed")
        self.assertTrue(Path(gaps[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_method_observation_recorded_correctly(self):
        _ctx, findings = self._run({
            "http_observations": [
                {
                    "url": "https://example.com/api/users/1234",
                    "method": "GET",
                    "headers": {},
                }
            ],
            "method_observations": [
                {"url": "https://example.com/api/users/1234", "method": "DELETE"},
                {"url": "https://example.com/api/users/1234", "method": "PATCH"},
            ],
        })
        method_findings = [
            f for f in findings
            if f.get("vuln_type") == "Access Control Method Observation"
        ]
        self.assertTrue(method_findings)
        self.assertEqual(method_findings[0]["severity"], "INFO")
        self.assertIn("DELETE", method_findings[0]["evidence"])

    def test_no_finding_marked_confirmed_without_full_artifact(self):
        recon = {
            "http_observations": [
                {
                    "url": "https://example.com/api/users/me",
                    "method": "GET",
                    "headers": {"Cookie": "sid=secret"},
                },
                {
                    "url": "https://example.com/api/users/me",
                    "method": "GET",
                    "headers": {},
                },
            ]
        }
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(recon, temp)
            with patch(
                "core.agents.access_control_agent.write_evidence_artifact",
                return_value={"artifact_path": "", "raw_request": ""},
            ):
                findings = asyncio.run(AccessControlAgent().run(ctx))
        self.assertTrue(findings)
        self.assertFalse(any(
            finding.get("exploitability_status") == "confirmed"
            for finding in findings
        ))

    def test_passive_mode_sends_no_additional_probe_requests(self):
        ctx, findings = self._run({
            "urls": ["https://example.com/api/users/1234"],
            "http_observations": [
                {
                    "url": "https://example.com/api/users/1234",
                    "method": "GET",
                    "headers": {},
                }
            ],
        })
        self.assertTrue(findings)
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertEqual(ctx.tested_urls, set())


if __name__ == "__main__":
    unittest.main()
