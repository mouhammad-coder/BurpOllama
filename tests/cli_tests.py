import io
import sys
import asyncio
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from rich.console import Console

import cli


BENCHMARK_LAB = "juice" + "-shop"
BENCHMARK_LABEL = "OWASP " + "Juice " + "Shop"
BENCHMARK_TARGET = "http://localhost" + ":" + "3000"


class CliTests(unittest.TestCase):
    def test_documented_commands_parse(self):
        parser = cli.build_parser()
        self.assertEqual(
            parser.parse_args(["scan", "https://example.test"]).mode,
            "passive",
        )
        ai_args = parser.parse_args([
            "scan",
            "https://example.test",
            "--ai",
            "--ai-provider",
            "ollama",
        ])
        self.assertTrue(ai_args.ai)
        self.assertEqual(ai_args.ai_provider, "ollama")
        self.assertTrue(
            parser.parse_args([
                "scan",
                "https://example.test",
                "--no-ai",
            ]).no_ai
        )
        self.assertEqual(
            parser.parse_args(["watch", "--scan-id", "abc123"]).scan_id,
            "abc123",
        )
        self.assertEqual(
            parser.parse_args(
                ["report", "--scan-id", "abc123", "--format", "sarif"]
            ).format,
            "sarif",
        )
        self.assertEqual(parser.parse_args(["doctor"]).command, "doctor")
        self.assertEqual(parser.parse_args(["serve"]).command, "serve")
        self.assertTrue(
            parser.parse_args(["benchmark", BENCHMARK_LAB, "--check"]).check
        )

    def test_cloudflare_event_switch_message_is_renderable(self):
        printer = cli.StreamPrinter("scan-1")
        with redirect_stdout(io.StringIO()):
            stopped = printer.handle({
                "type": "cloudflare_detected",
                "scan_id": "scan-1",
                "passive_fallback": True,
            })
        self.assertFalse(stopped)

    def test_finding_events_are_deduplicated(self):
        printer = cli.StreamPrinter("scan-1")
        finding = {
            "id": "F-1",
            "scan_id": "scan-1",
            "title": "Missing CSP",
            "severity": "MEDIUM",
            "url": "https://example.test",
        }
        with redirect_stdout(io.StringIO()):
            printer.handle({
                "type": "finding_live",
                "scan_id": "scan-1",
                "data": finding,
            })
            printer.handle({
                "type": "finding",
                "data": finding,
            })
        self.assertEqual(len(printer.finding_ids), 1)

    def test_print_results_includes_readiness_summary(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)
        scan = {
            "id": "scan-ready",
            "target": "https://example.test",
            "mode": "passive",
            "status": "complete",
            "recon": {"urls": ["https://example.test"]},
            "rate_limiter": {"total_requests": 3},
            "triaged_findings": [
                {"severity": "MEDIUM"},
                {"severity": "MEDIUM"},
                {"severity": "LOW"},
            ],
            "confirmed_findings": [],
            "candidate_findings": [],
            "analysis": {
                "coverage": {"coverage_percent": 12.5},
                "zero_fp_gate": {
                    "valid_bugs": [
                        {
                            "title": "Missing content-security-policy",
                            "vuln_type": "Missing Security Headers",
                            "severity": "MEDIUM",
                        },
                        {
                            "title": "Missing content-security-policy",
                            "vuln_type": "Missing Security Headers",
                            "severity": "MEDIUM",
                        },
                    ],
                    "needs_more_proof": [{"title": "SSRF candidate"}],
                    "candidates": [{"title": "Open redirect candidate"}],
                    "informational": [],
                },
            },
        }
        with patch.object(cli, "console", console):
            cli.print_results(scan, started=0)
        output = stream.getvalue()
        self.assertIn("Report-ready issues", output)
        self.assertIn("Manual-check findings", output)
        self.assertIn("Proof-blocked findings", output)
        self.assertIn("1", output)
        self.assertIn("2", output)

    def test_history_includes_readiness_counts(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)

        class _Store:
            def list(self):
                return [{
                    "scan_id": "scan-1",
                    "target": "https://example.test",
                    "status": "complete",
                    "phase": "complete",
                    "started_at": "2026-06-30T00:00:00Z",
                }]

            def get(self, scan_id):
                if scan_id != "scan-1":
                    raise AssertionError(scan_id)
                return {
                    "analysis": {
                        "zero_fp_gate": {
                            "valid_bugs": [{
                                "title": "Missing CSP",
                                "vuln_type": "Header",
                                "severity": "MEDIUM",
                            }],
                            "needs_more_proof": [{"title": "SSRF candidate"}],
                            "candidates": [{"title": "Open redirect"}],
                            "informational": [],
                        }
                    }
                }

        with patch.object(cli, "console", console), patch.object(cli, "scan_store", _Store()):
            code = asyncio.run(cli.command_history(SimpleNamespace()))
        output = stream.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Ready", output)
        self.assertIn("Manual", output)
        self.assertIn("Proof", output)
        self.assertIn("scan-1", output)

    def test_benchmark_check_reports_unreachable_target(self):
        class _Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, _target):
                raise httpx.ConnectError("refused")

        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=100)
        args = SimpleNamespace(lab=BENCHMARK_LAB, timeout=1.0)
        with patch.object(cli, "console", console), patch.object(cli.httpx, "AsyncClient", _Client):
            code = asyncio.run(cli.command_benchmark_check(
                args,
                {"label": BENCHMARK_LABEL},
                BENCHMARK_TARGET,
            ))
        self.assertEqual(code, 2)
        self.assertIn("not reachable", stream.getvalue())
        self.assertIn("docker run", stream.getvalue())

    def test_benchmark_check_reports_reachable_target(self):
        class _Response:
            status_code = 200
            text = BENCHMARK_LABEL

        class _Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, _target):
                return _Response()

        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=100)
        args = SimpleNamespace(lab=BENCHMARK_LAB, timeout=1.0)
        with patch.object(cli, "console", console), patch.object(cli.httpx, "AsyncClient", _Client):
            code = asyncio.run(cli.command_benchmark_check(
                args,
                {"label": BENCHMARK_LABEL},
                BENCHMARK_TARGET,
            ))
        self.assertEqual(code, 0)
        self.assertIn("Benchmark target reachable", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
