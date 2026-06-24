from __future__ import annotations

import asyncio
import io
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

import cli
from core.agents.header_agent import HeaderAgent
from core.events import EventType
from core.scope import ScanScope, is_in_scope, load_scope_file


class ScopeFileTests(unittest.TestCase):
    def test_wildcard_matches_subdomain_not_apex(self):
        scope = ScanScope("https://api.example.com", ["*.example.com"])
        self.assertTrue(scope.is_in_scope("https://api.example.com/v1"))
        self.assertFalse(scope.is_in_scope("https://example.com/"))

    def test_exclusion_overrides_wildcard_match(self):
        scope = ScanScope(
            "https://api.example.com",
            ["*.example.com", "!excluded.example.com"],
        )
        self.assertTrue(scope.is_in_scope("https://api.example.com"))
        self.assertFalse(scope.is_in_scope("https://excluded.example.com"))

    def test_url_prefix_blocks_out_of_path_requests(self):
        scope = ScanScope("https://example.com/api", ["https://example.com/api"])
        self.assertTrue(scope.is_in_scope("https://example.com/api/users"))
        self.assertFalse(scope.is_in_scope("https://example.com/admin"))

    def test_scope_check_command_prints_correct_result(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "scope.txt"
            path.write_text("*.example.com\n!excluded.example.com\n", encoding="utf-8")
            stream = io.StringIO()
            console = Console(file=stream, force_terminal=False, width=100)
            args = Namespace(scope_file=str(path), url="https://api.example.com")
            with patch.object(cli, "console", console):
                code = asyncio.run(cli.command_scope_check(args))
            self.assertEqual(code, 0)
            self.assertIn("IN SCOPE", stream.getvalue())

    def test_malformed_scope_file_line_warns_without_crash(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "scope.txt"
            path.write_text("*.example.com\nbad entry\n", encoding="utf-8")
            entries, warnings = load_scope_file(path)
            result, parse_warnings = is_in_scope("https://api.example.com", entries)
            self.assertTrue(result)
            self.assertTrue(warnings or parse_warnings)

    def test_agent_skips_and_logs_out_of_scope_url(self):
        class _Scheduler:
            def state(self, _name):
                return SimpleNamespace(findings=0, last_event="", status="pending")

            async def checkpoint(self):
                return None

        class _RateLimiter:
            async def acquire(self):
                raise AssertionError("out-of-scope URL should not be requested")

        class _Context:
            def __init__(self):
                self.scan = {"id": "scope-test", "target": "https://example.com"}
                self.options = SimpleNamespace(timeout=1.0, retries=0, concurrency=1)
                self.recon = {"urls": ["https://evil.example.net/login"]}
                self.raw_findings = []
                self.tested_urls = set()
                self.scheduler = _Scheduler()
                self.rate_limiter = _RateLimiter()
                self.scope = ScanScope("https://example.com", ["example.com"])
                self.events = []

            async def emit(self, event_type, **data):
                self.events.append((event_type, data))

        ctx = _Context()
        findings = asyncio.run(HeaderAgent().run(ctx))
        self.assertEqual(findings, [])
        self.assertEqual(ctx.tested_urls, set())
        self.assertTrue(any(
            event_type == EventType.SKIPPED
            and data.get("reason") == "out_of_scope"
            for event_type, data in ctx.events
        ))


if __name__ == "__main__":
    unittest.main()
