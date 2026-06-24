import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import EventType, ScanEvent, ScanEventBus
from core.ratelimit import RateLimiter
from core.scheduler import Scheduler
from core.scope import ScanScope
from core.storage import ScanStore


class CoreRuntimeTests(unittest.TestCase):
    def test_scope_defaults_to_target_and_blocks_external_hosts(self):
        scope = ScanScope("https://app.example.test")
        self.assertTrue(scope.allows("https://app.example.test/api"))
        self.assertFalse(scope.allows("https://cdn.app.example.test/api"))
        self.assertFalse(scope.allows("https://evil.test/api"))
        allowed, skipped = scope.filter([
            "https://app.example.test/a",
            "https://evil.test/b",
        ])
        self.assertEqual(len(allowed), 1)
        self.assertEqual(len(skipped), 1)

    def test_explicit_scope_uses_exact_and_wildcard_rules(self):
        scope = ScanScope(
            "https://app.example.test",
            ["app.example.test", "*.example.test"],
        )
        self.assertTrue(scope.allows("https://cdn.example.test/app.js"))
        self.assertTrue(scope.allows("https://app.example.test/app.js"))
        self.assertFalse(scope.allows("https://example.test/app.js"))
        self.assertFalse(scope.allows("https://example.invalid/app.js"))

    def test_event_bus_delivers_typed_events(self):
        events = []

        async def run():
            bus = ScanEventBus()
            bus.subscribe(events.append)
            await bus.emit(ScanEvent(
                type=EventType.AGENT_STARTED.value,
                scan_id="scan-1",
                agent="recon",
                message="started",
            ))

        asyncio.run(run())
        self.assertEqual(events[0]["agent"], "recon")

    def test_rate_limiter_counts_requests(self):
        async def run():
            limiter = RateLimiter(50, max_requests=2)
            await limiter.acquire()
            await limiter.acquire()
            with self.assertRaises(RuntimeError):
                await limiter.acquire()
            return limiter.snapshot()

        snapshot = asyncio.run(run())
        self.assertEqual(snapshot["total_requests"], 2)

    def test_scheduler_is_bounded_and_tracks_agents(self):
        async def run():
            scheduler = Scheduler(concurrency=2)

            async def operation():
                await asyncio.sleep(0)
                return "ok"

            result = await scheduler.run("recon", operation)
            return result, scheduler.snapshot()

        result, states = asyncio.run(run())
        self.assertEqual(result, "ok")
        self.assertEqual(states["recon"]["status"], "complete")

    def test_storage_tracks_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ScanStore(Path(directory) / "scans.db")
            report = Path(directory) / "report.md"
            report.write_text("# report", encoding="utf-8")
            store.save({
                "id": "scan-1",
                "target": "https://example.test",
                "mode": "passive",
                "status": "complete",
                "phase": "complete",
                "started": "now",
                "triaged_findings": [],
            }, [])
            store.save_report("scan-1", "markdown", report)
            self.assertEqual(store.reports("scan-1")["markdown"], str(report))


if __name__ == "__main__":
    unittest.main()
