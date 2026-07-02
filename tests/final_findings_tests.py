import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cli
from core.bug_registry import RATES, STATUSES, all_bug_types
from core.findings import (
    GREAT,
    INFO,
    MANUAL,
    REJECTED,
    final_findings,
    render_final_tables,
    write_scan_artifacts,
)


def scan_with(findings):
    return {
        "id": "scan-final",
        "target": "https://example.test",
        "goal": "bounty-hunt",
        "mode": "bounty",
        "recon": {"urls": ["https://example.test", "https://example.test/api"]},
        "agent_status": {"recon": {}, "proof": {}},
        "analysis": {
            "zero_fp_gate": {
                "valid_bugs": [],
                "needs_more_proof": [],
                "candidates": [],
                "informational": [],
                "false_positives_removed": [],
                "skipped_out_of_scope": [],
            }
        },
        "triaged_findings": findings,
    }


def finding(**overrides):
    data = {
        "id": "F-1",
        "title": "IDOR candidate in /api/orders/{id}",
        "vuln_type": "IDOR",
        "severity": "HIGH",
        "confidence": 91,
        "url": "https://api.example.test/api/orders/2",
        "business_impact": "Possible unauthorized data access",
        "evidence": "User A/User B response mismatch",
        "evidence_strength": "strong",
        "exploitability_status": "confirmed",
        "evidence_complete": True,
        "safe_manual_validation_steps": [
            "Verify impact with authorized test accounts."
        ],
    }
    data.update(overrides)
    return data


class FinalFindingsTests(unittest.TestCase):
    def test_final_great_and_manual_tables_render(self):
        scan = scan_with([
            finding(),
            finding(
                id="F-2",
                title="Possible BOLA on /api/users/{id}",
                vuln_type="BOLA",
                confidence=72,
                evidence="Object ID pattern found",
                evidence_strength="weak",
                exploitability_status="needs_manual_validation",
                evidence_complete=False,
            ),
        ])

        findings = final_findings(scan)
        output = render_final_tables(scan, findings)

        self.assertEqual(findings["counts"]["great"], 1)
        self.assertEqual(findings["counts"]["manual"], 1)
        self.assertIn("Great Findings", output)
        self.assertIn("Needs Manual Check", output)
        self.assertIn("Best Next Safe Actions", output)
        for section in (
            "Scan Finished",
            "Target:",
            "Goal",
            "Mode:",
            "Program:",
            "Scanner Permission:",
            "Great Findings",
            "Needs Manual Check",
            "Best Next Safe Actions",
        ):
            self.assertIn(section, output)
        self.assertIn("No second-user proof yet", output)
        self.assertIn("Test with two authorized accounts", output)
        forbidden = (
            "report-ready",
            "ready to submit",
            "report export",
            "hackerone draft",
            "bugcrowd draft",
            "sarif",
            "csv report",
        )
        lowered = output.lower()
        for phrase in forbidden:
            self.assertNotIn(phrase, lowered)

    def test_no_great_still_shows_manual_check(self):
        scan = scan_with([
            finding(
                confidence=64,
                title="Possible rate-limit weakness on /login",
                vuln_type="login rate-limit concern",
                severity="MEDIUM",
                evidence="No rate-limit headers observed",
                evidence_strength="weak",
                exploitability_status="candidate",
                evidence_complete=False,
            )
        ])
        output = render_final_tables(scan, final_findings(scan))
        self.assertIn("No great findings found.", output)
        self.assertIn("Needs Manual Check", output)
        self.assertIn("Check program rules", output)

    def test_no_useful_findings_prints_manual_opportunities(self):
        scan = scan_with([])
        output = render_final_tables(scan, final_findings(scan))
        self.assertIn("No great findings found.", output)
        self.assertIn("Manual-check opportunities:", output)

    def test_great_finding_requires_evidence_and_impact(self):
        scan = scan_with([
            finding(evidence_complete=False, evidence_strength="weak"),
            finding(id="F-2", title="Confirmed issue without impact", business_impact="", impact="", evidence_complete=True),
        ])
        statuses = [item["status"] for item in final_findings(scan)["all"]]
        self.assertIn(MANUAL, statuses)
        self.assertIn(INFO, statuses)
        self.assertNotIn(GREAT, statuses)

    def test_missing_header_only_hidden_by_default(self):
        scan = scan_with([
            finding(
                title="Missing content-security-policy",
                vuln_type="Missing Security Headers",
                severity="MEDIUM",
                confidence=90,
                business_impact="",
                evidence="content-security-policy header absent",
            )
        ])
        findings = final_findings(scan)
        self.assertEqual(findings["counts"]["great"], 0)
        self.assertEqual(findings["counts"]["manual"], 0)
        self.assertEqual(findings["counts"]["informational"], 1)

    def test_ai_only_finding_is_rejected(self):
        scan = scan_with([
            finding(source="ai-agent", evidence="", evidence_complete=False)
        ])
        self.assertEqual(final_findings(scan)["all"][0]["status"], REJECTED)

    def test_ai_worded_observation_without_artifact_is_rejected(self):
        scan = scan_with([
            finding(
                source="ai-agent",
                evidence_source="ai",
                evidence="Observed response mismatch in likely endpoint",
                evidence_complete=True,
            )
        ])
        item = final_findings(scan)["all"][0]
        self.assertEqual(item["status"], REJECTED)
        self.assertIn("ai_only_assumption", item["raw_status_reason"])

    def test_secrets_are_redacted_from_terminal_output(self):
        scan = scan_with([
            finding(evidence="Authorization: Bearer SECRETSECRETSECRET and admin@example.test")
        ])
        output = render_final_tables(scan, final_findings(scan))
        self.assertNotIn("SECRETSECRETSECRET", output)
        self.assertNotIn("admin@example.test", output)
        self.assertIn("[REDACTED]", output)

    def test_write_scan_artifacts_creates_allowed_files_only(self):
        scan = scan_with([finding()])
        with tempfile.TemporaryDirectory() as temp:
            paths = write_scan_artifacts(scan, temp)
            names = set(paths)
            self.assertEqual(names, {
                "findings.json",
                "evidence-board.json",
                "agent-messages.jsonl",
                "agent-decisions.jsonl",
                "agent-graph.json",
                "scan-log.jsonl",
            })
            self.assertTrue((Path(temp) / "scan-final" / "findings.json").exists())
            self.assertFalse((Path(temp) / "scan-final" / "report.md").exists())
            json.loads((Path(temp) / "scan-final" / "findings.json").read_text())

    def test_registry_entries_are_complete(self):
        self.assertGreaterEqual(len(all_bug_types()), 70)
        for bug in all_bug_types():
            data = bug.to_dict()
            for key in (
                "id",
                "name",
                "category",
                "default_rate",
                "minimum_evidence_for_great",
                "needs_manual_check_when",
                "common_false_positives",
                "safe_automated_checks",
                "unsafe_checks",
                "required_manual_verification",
                "impact_template",
            ):
                self.assertTrue(data[key], bug.id)
            self.assertIn(bug.default_rate, RATES)
        self.assertIn(GREAT, STATUSES)
        self.assertIn(MANUAL, STATUSES)

    def test_cli_findings_latest_json_and_filters(self):
        scan = scan_with([finding(), finding(id="F-2", severity="LOW", confidence=50)])

        class Store:
            def list(self, limit=1):
                return [{"scan_id": "scan-final"}]

            def get(self, scan_id):
                assert scan_id == "scan-final"
                return scan

        from rich.console import Console

        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=160)
        args = SimpleNamespace(
            scan_id=None,
            latest=True,
            show_info=False,
            show_rejected=False,
            show_all=False,
            json_output=True,
            min_rate="high",
            min_confidence=80,
        )
        with patch.object(cli, "scan_store", Store()), patch.object(cli, "console", console):
            code = __import__("asyncio").run(cli.command_findings(args))
        self.assertEqual(code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["rate"], "High")

    def test_report_command_is_deprecated(self):
        from rich.console import Console

        stream = io.StringIO()
        args = SimpleNamespace(scan_id="scan-final", latest=False, format="sarif", output=None)
        with patch.object(cli, "console", Console(file=stream, force_terminal=False)):
            code = __import__("asyncio").run(cli.command_report(args))
        self.assertEqual(code, 2)
        self.assertIn(
            "This command is deprecated. Use `burpollama findings --latest` instead.",
            stream.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
