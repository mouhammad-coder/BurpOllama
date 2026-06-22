import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fresh_scope_hunter as module
from fresh_scope_hunter import FreshScopeHunter, asset_to_target, parse_scope_feed


def _record(asset: str, fingerprint: str) -> dict:
    return {
        "fingerprint": fingerprint,
        "platform": "hackerone",
        "program_id": "example-program",
        "program_name": "Example Program",
        "program_url": "https://hackerone.com/example-program",
        "asset": asset,
        "asset_type": "url",
        "source_url": "https://example.invalid/feed.json",
    }


class FreshScopeHunterTests(unittest.TestCase):
    def test_parse_scope_feed_normalizes_multiple_platform_shapes(self):
        payload = [
            {
                "handle": "example-program",
                "name": "Example Program",
                "url": "https://example.invalid/policy",
                "targets": {
                    "in_scope": [
                        {"type": "url", "endpoint": "app.example.test"},
                        {"type": "wildcard", "endpoint": "*.api.example.test"},
                        {"type": "android", "endpoint": "com.example.mobile"},
                    ],
                    "out_of_scope": [
                        {"type": "url", "endpoint": "admin.example.test"}
                    ],
                },
            }
        ]
        records = parse_scope_feed("intigriti", payload, "feed")
        self.assertEqual(
            {record["asset"] for record in records},
            {"app.example.test", "*.api.example.test"},
        )

    def test_asset_to_target_refuses_wildcard_inference(self):
        self.assertEqual(
            asset_to_target("app.example.test"),
            "https://app.example.test",
        )
        self.assertEqual(
            asset_to_target("https://app.example.test/api"),
            "https://app.example.test/api",
        )
        self.assertEqual(asset_to_target("*.example.test"), "")

    def test_first_fetch_is_baseline_and_later_additions_are_queued(self):
        with tempfile.TemporaryDirectory() as directory:
            hunter = FreshScopeHunter(
                str(Path(directory) / "fresh.db"),
                str(Path(directory) / "fresh.json"),
            )
            baseline = _record("app.example.test", "hackerone|example|app")
            added = _record("api.example.test", "hackerone|example|api")

            self.assertEqual(
                hunter._store_records("hackerone", [baseline], baseline=True),
                [],
            )
            self.assertEqual(hunter.candidates(), [])

            fresh = hunter._store_records(
                "hackerone",
                [baseline, added],
                baseline=False,
            )
            self.assertEqual(
                [record["asset"] for record in fresh],
                ["api.example.test"],
            )
            self.assertEqual(hunter.candidates()[0]["status"], "queued")

    def test_authorized_auto_launch_requires_exact_saved_rule(self):
        async def run():
            with tempfile.TemporaryDirectory() as directory:
                hunter = FreshScopeHunter(
                    str(Path(directory) / "fresh.db"),
                    str(Path(directory) / "fresh.json"),
                )
                hunter.update_config(
                    {
                        "auto_launch": True,
                        "max_scans_per_run": 2,
                        "max_new_assets_per_run": 10,
                    },
                    persist=False,
                )
                hunter.authorize(
                    "hackerone",
                    "example-program",
                    ["api.example.test"],
                )

                calls = {"count": 0}

                async def fake_fetch(_client, platform, source_url):
                    calls["count"] += 1
                    record = _record(
                        "api.example.test",
                        "{}|example-program|api.example.test".format(platform),
                    )
                    return [record], {
                        "platform": platform,
                        "records": 1,
                        "baseline": False,
                    }

                launched = []

                async def launcher(record, target):
                    launched.append((record["program_id"], target))
                    return "scan-123"

                original_feeds = module.DEFAULT_FEEDS
                module.DEFAULT_FEEDS = {
                    "hackerone": "https://example.invalid/feed.json"
                }
                hunter._fetch_feed = fake_fetch
                try:
                    result = await hunter.check_now(launcher)
                finally:
                    module.DEFAULT_FEEDS = original_feeds

                self.assertEqual(calls["count"], 1)
                self.assertEqual(result["scans_started"], 1)
                self.assertEqual(
                    launched,
                    [("example-program", "https://api.example.test")],
                )
                candidate = hunter.candidates()[0]
                self.assertEqual(candidate["status"], "scan_started")
                self.assertEqual(candidate["scan_id"], "scan-123")

        asyncio.run(run())

    def test_unconfirmed_program_never_auto_launches(self):
        async def run():
            with tempfile.TemporaryDirectory() as directory:
                hunter = FreshScopeHunter(
                    str(Path(directory) / "fresh.db"),
                    str(Path(directory) / "fresh.json"),
                )
                hunter.update_config({"auto_launch": True}, persist=False)

                async def fake_fetch(_client, platform, source_url):
                    return [
                        _record(
                            "unauthorized.example.test",
                            "{}|example-program|unauthorized".format(platform),
                        )
                    ], {
                        "platform": platform,
                        "records": 1,
                        "baseline": False,
                    }

                async def launcher(_record_value, _target):
                    raise AssertionError("Unauthorized candidate must not launch")

                original_feeds = module.DEFAULT_FEEDS
                module.DEFAULT_FEEDS = {
                    "hackerone": "https://example.invalid/feed.json"
                }
                hunter._fetch_feed = fake_fetch
                try:
                    result = await hunter.check_now(launcher)
                finally:
                    module.DEFAULT_FEEDS = original_feeds

                self.assertEqual(result["scans_started"], 0)
                self.assertEqual(
                    hunter.candidates()[0]["status"],
                    "awaiting_authorization",
                )

        asyncio.run(run())

    def test_authorized_wildcard_uses_optional_chaos_enrichment(self):
        async def run():
            with tempfile.TemporaryDirectory() as directory:
                hunter = FreshScopeHunter(
                    str(Path(directory) / "fresh.db"),
                    str(Path(directory) / "fresh.json"),
                )
                hunter.update_config(
                    {"auto_launch": True, "max_scans_per_run": 2},
                    persist=False,
                )
                hunter.authorize(
                    "hackerone",
                    "example-program",
                    ["*.example.test"],
                )

                async def fake_fetch(_client, platform, source_url):
                    return [
                        _record(
                            "*.example.test",
                            "{}|example-program|wildcard".format(platform),
                        )
                    ], {
                        "platform": platform,
                        "records": 1,
                        "baseline": False,
                    }

                async def fake_chaos(_domain, limit=100):
                    return ["api.example.test", "app.example.test"][:limit]

                launched = []

                async def launcher(_record_value, target):
                    launched.append(target)
                    return "scan-{}".format(len(launched))

                original_feeds = module.DEFAULT_FEEDS
                module.DEFAULT_FEEDS = {
                    "hackerone": "https://example.invalid/feed.json"
                }
                hunter._fetch_feed = fake_fetch
                hunter.chaos_subdomains = fake_chaos
                try:
                    result = await hunter.check_now(launcher)
                finally:
                    module.DEFAULT_FEEDS = original_feeds

                self.assertEqual(result["scans_started"], 2)
                self.assertEqual(
                    launched,
                    [
                        "https://api.example.test",
                        "https://app.example.test",
                    ],
                )

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
