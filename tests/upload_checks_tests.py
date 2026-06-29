from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.agents.upload_agent import UploadAgent


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
    def __init__(self, recon, output, mode="bounty"):
        self.scan = {
            "id": "upload-checks-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(mode=mode, timeout=1.0)
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))


class UploadChecksTests(unittest.TestCase):
    def _run(self, recon, mode="bounty"):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name, mode=mode)
        findings = asyncio.run(UploadAgent().run(ctx))
        return ctx, findings

    def test_multipart_form_detected(self):
        _ctx, findings = self._run({
            "forms": [{
                "action": "https://example.com/profile/avatar",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "avatar", "type": "file", "accept": "image/png,image/jpeg"}],
            }]
        })
        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["vuln_type"], "File Upload Endpoint Candidate")
        self.assertEqual(finding["exploitability_status"], "candidate")
        artifact = finding["evidence_artifact"]
        self.assertTrue(Path(artifact["artifact_path"]).exists())
        self.assertEqual(artifact["metadata"]["detection_method"], "multipart form enctype")
        self.assertEqual(artifact["metadata"]["parameter_name"], "avatar")
        self.assertIn("image/png", artifact["metadata"]["accepted_types"])

    def test_file_parameter_flagged(self):
        _ctx, findings = self._run({
            "urls": ["https://example.com/import?file=users.csv"]
        })
        self.assertTrue(findings)
        self.assertEqual(findings[0]["parameter"], "file")
        self.assertEqual(findings[0]["vuln_type"], "File Upload Endpoint Candidate")

    def test_file_path_in_response_escalates_confidence(self):
        _ctx, baseline = self._run({
            "urls": ["https://example.com/import?file=users.csv"]
        })
        _ctx, escalated = self._run({
            "urls": ["https://example.com/import?file=users.csv"],
            "http_observations": [{
                "url": "https://example.com/import?file=users.csv",
                "status_code": 200,
                "body": "Imported users.csv to /uploads/2026/users.csv",
            }],
        })
        self.assertGreater(escalated[0]["confidence"], baseline[0]["confidence"])
        artifact = escalated[0]["evidence_artifact"]
        self.assertTrue(artifact["metadata"]["file_path_observed"])
        self.assertTrue(artifact["metadata"]["reflected_filename"])
        self.assertIn("/uploads/2026/users.csv", artifact["metadata"]["response_snippet_first_512"])

    def test_no_upload_requests_sent_ever(self):
        ctx, findings = self._run({
            "forms": [{
                "action": "https://example.com/upload",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "file", "type": "file"}],
            }],
            "http_observations": [{
                "url": "https://example.com/upload",
                "headers": {"Content-Type": "multipart/form-data; boundary=abc"},
                "body": "Upload failed at /var/www/app/uploads/file.txt",
            }],
        })
        self.assertTrue(findings)
        self.assertEqual(ctx.tested_urls, set())
        self.assertEqual(ctx.rate_limiter.calls, 0)

    def test_passive_mode_still_detects_observation_only(self):
        ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/documents",
                "headers": {"Content-Type": "multipart/form-data; boundary=abc"},
                "body": "ok",
            }]
        }, mode="passive")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["vuln_type"], "File Upload Endpoint Candidate")
        self.assertEqual(ctx.tested_urls, set())
        self.assertEqual(ctx.rate_limiter.calls, 0)


if __name__ == "__main__":
    unittest.main()
