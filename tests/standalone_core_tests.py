import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scanner import Scanner
from core.storage import ScanStore


class StandaloneCoreTests(unittest.TestCase):
    def test_scan_runs_without_http_api_and_is_persisted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScanStore(Path(temp_dir) / "scans.db")
            local_scanner = Scanner(store=store)
            events = []

            async def target_check(context):
                return None

            async def recon(context):
                context.recon = {
                    "urls": [context.scan["target"]],
                    "live_hosts": [{"url": context.scan["target"], "tech": []}],
                    "tech_stack": [],
                }
                context.scan["recon"] = context.recon

            async def hunt(context):
                finding = {
                    "id": "finding-1",
                    "scan_id": context.scan["id"],
                    "title": "Test candidate",
                    "vuln_type": "Test candidate",
                    "url": context.scan["target"],
                    "severity": "LOW",
                    "verdict": "NEEDS_MANUAL_REVIEW",
                }
                context.raw_findings = [finding]
                context.scan["raw_findings"] = [finding]

            async def triage(context):
                context.triaged_findings = list(context.raw_findings)
                context.scan["triaged_findings"] = context.triaged_findings

            async def proof(context):
                context.scan["analysis"] = {"coverage": {}}

            async def report(context):
                context.scan["report"] = "# Standalone report"
                context.scan["report_paths"] = {}

            local_scanner._target_check = target_check
            local_scanner._recon = recon
            local_scanner._vulnerability_hunt = hunt
            local_scanner._ai_triage = triage
            local_scanner._proof_validation = proof
            local_scanner._report_export = report

            result = asyncio.run(local_scanner.run(
                "https://authorized.example",
                "passive",
                event_callback=events.append,
                output=temp_dir,
            ))
            self.assertEqual(result["status"], "complete")
            self.assertTrue(events)
            stored = store.get(result["id"])
            self.assertEqual(stored["report"], "# Standalone report")
            self.assertEqual(store.list()[0]["scan_id"], result["id"])

    def test_active_scan_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScanStore(Path(temp_dir) / "scans.db")
            with self.assertRaises(PermissionError):
                Scanner(store=store).prepare(
                    "https://authorized.example",
                    "bounty",
                    authorization_confirmed=False,
                )

    def test_default_scope_is_target_host(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScanStore(Path(temp_dir) / "scans.db")
            scan = Scanner(store=store).prepare(
                "https://app.example.test",
                "passive",
            )
            self.assertEqual(
                scan["scope"]["allowed_domains"],
                ["app.example.test"],
            )
            self.assertFalse(scan["scope"]["include_subdomains"])

    def test_stop_writes_partial_report_and_persists_interrupted_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScanStore(Path(temp_dir) / "scans.db")
            local_scanner = Scanner(store=store)
            partial_report = Path(temp_dir) / "partial.md"

            async def target_check(context):
                return None

            async def slow_recon(context):
                async def operation():
                    context.raw_findings = [{
                        "id": "partial-finding",
                        "title": "Partial finding",
                        "severity": "LOW",
                        "url": context.scan["target"],
                    }]
                    context.scan["raw_findings"] = list(context.raw_findings)
                    await asyncio.sleep(30)

                await context.scheduler.run("recon", operation)

            async def write_partial(context):
                partial_report.write_text(
                    "# Partial report\n\nScan interrupted safely.",
                    encoding="utf-8",
                )
                context.scan["report_paths"] = {
                    "markdown": str(partial_report)
                }

            local_scanner._target_check = target_check
            local_scanner._recon = slow_recon
            local_scanner._safe_partial_report = write_partial

            async def run():
                scan, task = local_scanner.start_background(
                    "https://authorized.example",
                    "passive",
                    output=temp_dir,
                )
                for _ in range(100):
                    if scan["id"] in local_scanner.active_contexts:
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(local_scanner.stop(scan["id"]))
                return await task

            result = asyncio.run(run())
            self.assertEqual(result["status"], "interrupted")
            self.assertTrue(partial_report.exists())
            stored = store.get(result["id"])
            self.assertEqual(stored["status"], "interrupted")
            self.assertEqual(
                stored["report_paths"]["markdown"],
                str(partial_report),
            )


if __name__ == "__main__":
    unittest.main()
