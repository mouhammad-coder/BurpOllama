import asyncio
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scanner import Scanner
from core.storage import ScanStore
from tests.e2e_pipeline_test import MockTargetHandler, ThreadingHTTPServer


class StandaloneScannerE2ETests(unittest.TestCase):
    def test_passive_scanner_runs_without_fastapi(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), MockTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = "http://127.0.0.1:{}".format(server.server_port)
                store = ScanStore(Path(directory) / "scans.db")
                scanner = Scanner(store=store)
                events = []
                scan = asyncio.run(scanner.run(
                    target,
                    "passive",
                    event_callback=events.append,
                    output=directory,
                    rate_limit=50,
                    concurrency=3,
                ))
                self.assertEqual(scan["status"], "complete")
                self.assertGreaterEqual(len(scan["recon"]["urls"]), 4)
                self.assertTrue(any(
                    finding.get("vuln_type") == "Missing Security Headers"
                    for finding in scan["triaged_findings"]
                ))
                self.assertTrue(any(
                    finding.get("vuln_type") == "Environment File Exposed"
                    for finding in scan["triaged_findings"]
                ))
                self.assertTrue(Path(scan["report_paths"]["markdown"]).exists())
                self.assertTrue(any(
                    event.get("type") == "agent_started"
                    for event in events
                ))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
