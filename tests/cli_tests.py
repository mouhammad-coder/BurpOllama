import io
import json
import sys
import asyncio
import tempfile
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
        self.assertTrue(parser.parse_args(["findings", "--latest"]).latest)
        self.assertTrue(parser.parse_args(["findings", "--latest", "--show-info"]).show_info)
        self.assertTrue(parser.parse_args(["findings", "--latest", "--show-rejected"]).show_rejected)
        self.assertTrue(parser.parse_args(["findings", "--latest", "--show-all"]).show_all)
        self.assertTrue(parser.parse_args(["findings", "--latest", "--json"]).json_output)
        self.assertEqual(parser.parse_args(["findings", "--latest", "--min-rate", "high"]).min_rate, "high")
        self.assertEqual(parser.parse_args(["findings", "--latest", "--min-confidence", "80"]).min_confidence, 80)
        self.assertTrue(parser.parse_args(["history", "--ready-only"]).ready_only)
        self.assertTrue(
            parser.parse_args(["readiness-check", "--latest", "--require-great-finding"]).require_great_finding
        )
        self.assertTrue(parser.parse_args(["readiness-check", "--latest", "--json"]).json)
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

    def test_print_results_includes_final_findings_summary(self):
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
                                "url": "https://example.test/admin",
                                "confidence": 94,
                                "business_impact": "Sensitive browser-side controls are missing on an admin surface.",
                                "evidence_complete": True,
                                "evidence_artifact": {"artifact_path": "evidence/scan/header-csp.json"},
                            },
                            {
                                "title": "Missing content-security-policy",
                                "vuln_type": "Missing Security Headers",
                                "severity": "MEDIUM",
                                "url": "https://example.test/account",
                                "business_impact": "Sensitive browser-side controls are missing on an account surface.",
                                "evidence_complete": True,
                            },
                        ],
                    "needs_more_proof": [{"title": "SSRF candidate", "url": "https://example.test/fetch", "confidence": 60, "severity": "HIGH", "business_impact": "Could trigger server-side fetches."}],
                    "candidates": [{"title": "Open redirect candidate", "confidence": 60, "severity": "MEDIUM", "business_impact": "Could redirect users externally."}],
                    "informational": [],
                },
            },
        }
        with patch.object(cli, "console", console):
            cli.print_results(scan, started=0)
        output = stream.getvalue()
        self.assertIn("Scan Finished", output)
        self.assertIn("Great Findings", output)
        self.assertIn("Needs Manual Check", output)
        self.assertIn("content-security-policy", output)
        self.assertIn("https://example.test/adm", output)
        self.assertIn("Manual validation required", output)
        self.assertIn("1", output)
        self.assertIn("2", output)

    def test_history_includes_readiness_counts(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)

        class _Store:
            def list(self, limit=100):
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
        self.assertIn("Great", output)
        self.assertIn("Manual", output)
        self.assertIn("Proof", output)
        self.assertIn("scan-1", output)

    def test_history_ready_only_filters_empty_scans(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)

        class _Store:
            def list(self, limit=100):
                return [
                    {"scan_id": "empty", "target": "https://empty.test", "status": "complete", "started_at": "1"},
                    {"scan_id": "ready", "target": "https://ready.test", "status": "complete", "started_at": "2"},
                ][:limit]

            def get(self, scan_id):
                if scan_id == "ready":
                    return {
                        "analysis": {
                            "zero_fp_gate": {
                                "valid_bugs": [{"title": "Ready", "severity": "MEDIUM"}],
                                "needs_more_proof": [],
                                "candidates": [],
                                "informational": [],
                            }
                        }
                    }
                return {"analysis": {"zero_fp_gate": {}}}

        with patch.object(cli, "console", console), patch.object(cli, "scan_store", _Store()):
            code = asyncio.run(cli.command_history(SimpleNamespace(ready_only=True, limit=100)))
        output = stream.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ready", output)
        self.assertNotIn("empty", output)

    def test_findings_latest_uses_most_recent_scan(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)

        class _Store:
            def list(self, limit=100):
                return [{"scan_id": "latest"}]

            def get(self, scan_id):
                if scan_id != "latest":
                    raise AssertionError(scan_id)
                return {
                    "id": "latest",
                    "target": "https://example.test",
                    "analysis": {"zero_fp_gate": {}},
                    "triaged_findings": [],
                }

        args = SimpleNamespace(
            scan_id=None,
            latest=True,
            show_info=False,
            show_rejected=False,
            show_all=False,
            json_output=False,
            min_rate="",
            min_confidence=0,
        )
        with patch.object(cli, "console", console), patch.object(cli, "scan_store", _Store()):
            code = asyncio.run(cli.command_findings(args))
        self.assertEqual(code, 0)
        self.assertIn("Scan Finished", stream.getvalue())

    def test_readiness_check_is_deprecated_and_does_not_write_json(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "readiness.json"
            args = SimpleNamespace(
                scan_id="scan-manual",
                latest=False,
                require_great_finding=False,
                json=True,
                output=str(output),
            )
            with patch.object(cli, "console", console):
                code = asyncio.run(cli.command_readiness_check(args))
            self.assertFalse(output.exists())
        self.assertEqual(code, 2)
        self.assertIn(
            "This command is deprecated. Use `burpollama findings --latest` instead.",
            stream.getvalue(),
        )

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
