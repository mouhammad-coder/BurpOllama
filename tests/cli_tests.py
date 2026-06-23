import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cli


class CliTests(unittest.TestCase):
    def test_documented_commands_parse(self):
        parser = cli.build_parser()
        self.assertEqual(
            parser.parse_args(["scan", "https://example.test"]).mode,
            "bounty",
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


if __name__ == "__main__":
    unittest.main()
