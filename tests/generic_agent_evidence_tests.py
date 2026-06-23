from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.crawler_agent import CrawlerAgent
from core.agents.header_agent import HeaderAgent
from core.agents.injection_agent import InjectionAgent
from core.agents.xss_agent import XSSAgent


class _MockHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, _fmt, *_args):
        return

    def _send(self, status=200, body="", ctype="text/html", headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/headers":
            self._send(200, "<html><body>missing headers</body></html>")
        elif path == "/admin":
            self._send(403, "Forbidden admin panel", "text/plain")
        elif path == "/.env":
            self._send(200, "DB_PASSWORD=secret123", "text/plain")
        elif path == "/search":
            if "%27" in query or "'" in query:
                self._send(
                    500,
                    "You have an error in your SQL syntax near quote",
                    "text/plain",
                )
            else:
                self._send(200, "normal search", "text/plain")
        elif path == "/baseline-error":
            self._send(
                500,
                "You have an error in your SQL syntax near quote",
                "text/plain",
            )
        elif path == "/reflect":
            value = query.split("q=", 1)[1] if "q=" in query else ""
            from urllib.parse import unquote_plus

            self._send(200, "<html><body>{}</body></html>".format(unquote_plus(value)))
        else:
            self._send(404, "Not found", "text/plain")


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
    async def acquire(self):
        return 0


class _Scope:
    def __init__(self, prefix):
        self.prefix = prefix

    def allows(self, url):
        return str(url).startswith(self.prefix)


class _Context:
    def __init__(self, target, urls, mode="bounty", output=None):
        self.scan = {
            "id": "agent-evidence-test",
            "target": target,
            "options": {"output": output or tempfile.gettempdir()},
        }
        self.options = SimpleNamespace(
            mode=mode,
            timeout=3.0,
            retries=0,
            concurrency=2,
        )
        self.recon = {"urls": urls, "js_findings": []}
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope(target)
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))

    async def log(self, message, level="info", **kwargs):
        self.events.append(("log", {"message": message, "level": level, **kwargs}))


class GenericAgentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.port = cls.server.server_address[1]
        cls.base = "http://127.0.0.1:{}".format(cls.port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_header_agent_writes_confirmed_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/headers"], output=temp)
            findings = asyncio.run(HeaderAgent().run(ctx))
            confirmed = [f for f in findings if f.get("exploitability_status") == "confirmed"]
            self.assertTrue(confirmed)
            artifact = confirmed[0]["evidence_artifact"]
            self.assertTrue(Path(artifact["artifact_path"]).exists())
            saved = json.loads(Path(artifact["artifact_path"]).read_text())
        for key in (
            "scan_id", "agent", "vuln_class", "url", "raw_request",
            "raw_response", "matched_indicator", "indicator_location",
            "impact", "fp_check", "confirmed", "timestamp", "artifact_path",
        ):
            self.assertIn(key, saved)
            if key != "confirmed":
                self.assertTrue(saved[key])
        self.assertEqual(saved["agent"], "header")

    def test_header_empty_artifact_demotes_to_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/headers"], output=temp)
            with patch(
                "core.agents.header_agent.write_evidence_artifact",
                return_value={"artifact_path": "", "raw_request": ""},
            ):
                findings = asyncio.run(HeaderAgent().run(ctx))
        self.assertTrue(findings)
        self.assertTrue(all(f.get("exploitability_status") != "confirmed" for f in findings))

    def test_injection_agent_confirms_only_after_baseline_diff_and_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/search?q=test"], output=temp)
            findings = asyncio.run(InjectionAgent().run(ctx))
            self.assertTrue(findings)
            self.assertEqual(findings[0]["exploitability_status"], "confirmed")
            self.assertTrue(Path(findings[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_injection_baseline_error_is_candidate_not_confirmed(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/baseline-error?q=test"], output=temp)
            findings = asyncio.run(InjectionAgent().run(ctx))
            self.assertTrue(findings)
            self.assertTrue(all(f.get("exploitability_status") != "confirmed" for f in findings))

    def test_injection_passive_mode_sends_no_payloads(self):
        ctx = _Context(self.base, [self.base + "/search?q=test"], mode="passive")
        findings = asyncio.run(InjectionAgent().run(ctx))
        self.assertEqual(findings, [])
        self.assertEqual(ctx.tested_urls, set())

    def test_xss_agent_safe_probe_writes_confirmed_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/reflect?q=test"], output=temp)
            findings = asyncio.run(XSSAgent().run(ctx))
            self.assertTrue(findings)
            self.assertEqual(findings[0]["exploitability_status"], "confirmed")
            artifact = findings[0]["evidence_artifact"]
            self.assertTrue(Path(artifact["artifact_path"]).exists())
            self.assertIn("<burpollama-probe-", artifact["matched_indicator"])

    def test_xss_empty_artifact_demotes_to_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/reflect?q=test"], output=temp)
            with patch(
                "core.agents.xss_agent.write_evidence_artifact",
                return_value={"artifact_path": "", "raw_request": ""},
            ):
                findings = asyncio.run(XSSAgent().run(ctx))
        self.assertTrue(findings)
        self.assertTrue(all(f.get("exploitability_status") != "confirmed" for f in findings))

    def test_xss_passive_mode_sends_no_payloads(self):
        ctx = _Context(self.base, [self.base + "/reflect?q=test"], mode="passive")
        findings = asyncio.run(XSSAgent().run(ctx))
        self.assertEqual(findings, [])
        self.assertEqual(ctx.tested_urls, set())

    def test_crawler_exposed_path_writes_confirmed_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/admin", self.base + "/.env"], output=temp)
            asyncio.run(CrawlerAgent().run(ctx))
            findings = ctx.raw_findings
            self.assertTrue(findings)
            confirmed = [f for f in findings if f.get("exploitability_status") == "confirmed"]
            self.assertTrue(confirmed)
            self.assertTrue(Path(confirmed[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_crawler_empty_artifact_demotes_to_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context(self.base, [self.base + "/admin"], output=temp)
            with patch(
                "core.agents.crawler_agent.write_evidence_artifact",
                return_value={"artifact_path": "", "raw_request": ""},
            ):
                asyncio.run(CrawlerAgent().run(ctx))
        self.assertTrue(ctx.raw_findings)
        self.assertTrue(all(f.get("exploitability_status") != "confirmed" for f in ctx.raw_findings))


if __name__ == "__main__":
    unittest.main()
