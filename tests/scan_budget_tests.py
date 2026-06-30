from __future__ import annotations

import asyncio
import tempfile
import unittest
from types import SimpleNamespace

import cli
from core.scanner import ScanOptions, Scanner
from core.storage import ScanStore


class ScanBudgetTests(unittest.TestCase):
    def test_scan_options_clamp_max_urls(self):
        self.assertEqual(ScanOptions(max_urls=0).max_urls, 1)
        self.assertEqual(ScanOptions(max_urls=5000).max_urls, 2000)
        self.assertEqual(ScanOptions(max_urls=25).max_urls, 25)

    def test_scan_options_clamp_time_budget(self):
        self.assertEqual(ScanOptions(time_budget=0).time_budget, 1)
        self.assertEqual(ScanOptions(time_budget=9000).time_budget, 7200)
        self.assertEqual(ScanOptions(time_budget=45).time_budget, 45)

    def test_cli_scan_exposes_budget_options(self):
        parser = cli.build_parser()
        args = parser.parse_args([
            "scan",
            "https://example.test",
            "--max-urls",
            "17",
            "--time-budget",
            "30",
        ])
        self.assertEqual(args.max_urls, 17)
        self.assertEqual(args.time_budget, 30)

    def test_scanner_prepare_stores_max_urls(self):
        scanner = Scanner()
        scan = scanner.prepare(
            "https://example.test",
            "passive",
            allowed_domains=["example.test"],
            max_urls=9,
        )
        self.assertEqual(scan["options"]["max_urls"], 9)

    def test_time_budget_interrupts_scan_and_writes_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scanner = Scanner(store=ScanStore("{}/scans.db".format(temp_dir)))
            scan = scanner.prepare(
                "https://example.test",
                "passive",
                allowed_domains=["example.test"],
                output=temp_dir,
                time_budget=1,
                ai_enabled=False,
            )

            async def no_ai(context):
                context.scan["ai"] = {
                    "requested": False,
                    "agents_enabled": False,
                    "triage_capable": False,
                    "active_provider": "none",
                    "active_model": "none",
                }
                return context.scan["ai"]

            async def slow_phases(context):
                await asyncio.sleep(2)

            scanner._configure_ai = no_ai
            scanner._run_phases = slow_phases

            result = asyncio.run(scanner.run_prepared(scan))

        self.assertEqual(result["status"], "interrupted")
        self.assertIn("time budget", result["error"].lower())

    def test_url_budget_trims_recon_urls_and_records_skipped(self):
        scanner = Scanner()
        events = []

        async def emit(event_type, **data):
            events.append({"type": event_type.value if hasattr(event_type, "value") else event_type, **data})

        context = SimpleNamespace(
            options=SimpleNamespace(max_urls=2),
            recon={"urls": [
                "https://example.test/a",
                "https://example.test/b",
                "https://example.test/c",
                "https://example.test/b",
            ]},
            scan={},
            emit=emit,
        )

        asyncio.run(scanner._enforce_url_budget(context, agent="recon"))

        self.assertEqual(context.recon["urls"], [
            "https://example.test/a",
            "https://example.test/b",
        ])
        self.assertEqual(context.recon["skipped_by_budget"], [
            "https://example.test/c",
        ])
        self.assertEqual(events[0]["reason"], "url_budget_exceeded")
        self.assertEqual(events[0]["skipped_count"], 1)


if __name__ == "__main__":
    unittest.main()
