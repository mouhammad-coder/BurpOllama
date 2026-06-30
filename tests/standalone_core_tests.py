import asyncio
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scanner import Scanner
from core.storage import ScanStore
from core.evidence import write_evidence_artifact


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

    def test_proof_and_reports_split_ready_vs_manual_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScanStore(Path(temp_dir) / "scans.db")
            local_scanner = Scanner(store=store)
            target = "https://example.test/search?q=1"
            evidence_dir = None

            async def target_check(context):
                return None

            async def recon(context):
                context.recon = {
                    "urls": [target],
                    "live_hosts": [{"url": "https://example.test", "tech": []}],
                    "tech_stack": [],
                }
                context.scan["recon"] = context.recon

            async def hunt(context):
                nonlocal evidence_dir
                artifact = write_evidence_artifact(
                    context.scan,
                    title="SQL injection confirmed by response difference",
                    url=target,
                    raw_request="GET /search?q=%27 HTTP/1.1\nHost: example.test",
                    raw_response="HTTP/1.1 500\nContent-Type: text/plain\n\nSQL syntax error near quote",
                    matched_indicator="SQL syntax error",
                    indicator_location="response body",
                    agent="test-fixture",
                    vuln_class="SQL Injection",
                    impact="An attacker can alter database queries and potentially read sensitive records.",
                    fp_check="Baseline response was HTTP 200 and payload response was HTTP 500 with a SQL parser error.",
                    confirmed=True,
                    filename_prefix="test-sqli",
                )
                evidence_dir = Path("evidence") / context.scan["id"]
                ready = {
                    "id": "ready-sqli",
                    "scan_id": context.scan["id"],
                    "title": "SQL injection confirmed by response difference",
                    "vuln_type": "SQL Injection",
                    "vulnerability_class": "SQL Injection",
                    "url": target,
                    "affected_url": target,
                    "method": "GET",
                    "severity": "HIGH",
                    "confidence": 95,
                    "description": "Payload changed the response from baseline to a SQL parser error.",
                    "evidence": "HTTP/1.1 500 response body contains SQL syntax error near quote",
                    "business_impact": "An attacker can alter database queries and potentially read sensitive records.",
                    "reproduction_steps": [
                        "Send a baseline request to /search?q=1.",
                        "Send /search?q=' within authorized scope.",
                        "Observe the SQL parser error only on the payload response.",
                    ],
                    "remediation": "Use parameterized queries and avoid string concatenation in SQL.",
                    "exploitability_status": "confirmed",
                    "evidence_strength": "strong",
                    "false_positive_risk": "low",
                    "redaction_status": "redacted",
                    "evidence_artifact": artifact,
                }
                blocked = {
                    "id": "blocked-cors",
                    "scan_id": context.scan["id"],
                    "title": "Confirmed-looking CORS finding without artifact",
                    "vuln_type": "CORS Misconfiguration",
                    "vulnerability_class": "CORS Misconfiguration",
                    "url": "https://example.test/api/account",
                    "affected_url": "https://example.test/api/account",
                    "method": "GET",
                    "severity": "MEDIUM",
                    "confidence": 82,
                    "description": "Credentialed CORS origin reflection was observed but lacks durable artifact proof.",
                    "evidence": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true",
                    "business_impact": "A malicious allowed origin could read authenticated API responses.",
                    "reproduction_steps": [
                        "Send a request with Origin: https://attacker.example.",
                        "Observe Access-Control-Allow-Origin reflects that origin.",
                        "Observe Access-Control-Allow-Credentials: true.",
                    ],
                    "remediation": "Use a strict CORS allowlist and avoid credentialed reflected origins.",
                    "exploitability_status": "confirmed",
                    "evidence_strength": "strong",
                    "false_positive_risk": "low",
                    "redaction_status": "redacted",
                    "evidence_artifact": {},
                }
                context.raw_findings = [ready, blocked]
                context.scan["raw_findings"] = list(context.raw_findings)

            async def triage(context):
                context.triaged_findings = list(context.raw_findings)
                context.scan["triaged_findings"] = context.triaged_findings

            local_scanner._target_check = target_check
            local_scanner._recon = recon
            local_scanner._vulnerability_hunt = hunt
            local_scanner._ai_triage = triage

            try:
                result = asyncio.run(local_scanner.run(
                    target,
                    "bounty",
                    authorization_confirmed=True,
                    output=temp_dir,
                    ai_enabled=False,
                ))
            finally:
                if evidence_dir and evidence_dir.exists():
                    shutil.rmtree(evidence_dir)

            self.assertEqual(result["status"], "complete")
            self.assertEqual(
                [finding["title"] for finding in result["confirmed_findings"]],
                ["SQL injection confirmed by response difference"],
            )
            manual_titles = [
                finding["title"]
                for finding in result["candidate_findings"]
            ]
            self.assertIn("Confirmed-looking CORS finding without artifact", manual_titles)

            json_report = json.loads(Path(result["report_paths"]["json"]).read_text())
            self.assertEqual(
                [finding["title"] for finding in json_report["confirmed_findings"]],
                ["SQL injection confirmed by response difference"],
            )
            self.assertEqual(
                [finding["title"] for finding in json_report["candidate_findings"]],
                ["Confirmed-looking CORS finding without artifact"],
            )

            h1_report = Path(result["report_paths"]["hackerone"]).read_text()
            self.assertIn("## [High] SQL injection confirmed by response difference", h1_report)
            self.assertIn("Confirmed-looking CORS finding without artifact", h1_report)
            self.assertNotIn("## [Medium] Confirmed-looking CORS finding without artifact", h1_report)

            readiness_report = Path(result["report_paths"]["readiness"]).read_text()
            self.assertIn("# Bounty Readiness Audit", readiness_report)
            self.assertIn("- Report-ready issues: 1", readiness_report)
            self.assertIn("Confirmed-looking CORS finding without artifact", readiness_report)

            sarif = json.loads(Path(result["report_paths"]["sarif"]).read_text())
            sarif_messages = [
                item["message"]["text"]
                for item in sarif["runs"][0]["results"]
            ]
            self.assertTrue(any(
                "SQL injection confirmed by response difference" in message
                for message in sarif_messages
            ))
            self.assertFalse(any(
                "Confirmed-looking CORS finding without artifact" in message
                for message in sarif_messages
            ))

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
