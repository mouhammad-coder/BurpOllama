from __future__ import annotations

import tempfile
import unittest
import asyncio
import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import cli
from core.reports import render_report, write_report_bundle
from reporter import generate_full_report


def _finding(status="confirmed", title="Missing content-security-policy"):
    return {
        "id": "finding-1",
        "title": title,
        "vuln_type": "Missing Security Headers",
        "severity": "MEDIUM",
        "confidence": 94,
        "url": "https://example.com",
        "exploitability_status": status,
        "reproduction_steps": [
            "Send GET / with an authorized test session.",
            "Inspect the response headers.",
            "Confirm the content-security-policy header is absent.",
        ],
        "safe_manual_validation_steps": [
            "Validate only within authorized scope.",
            "Reproduce with a low-rate request.",
        ],
        "evidence_artifact": {
            "artifact_path": "evidence/scan/header-csp.json",
            "matched_indicator": "content-security-policy",
            "indicator_location": "response headers",
            "vuln_class": "Missing Security Headers",
            "impact": "Missing CSP weakens browser-side injection defenses.",
        },
    }


def _scan(findings):
    return {
        "id": "scan-h1",
        "target": "https://example.com",
        "triaged_findings": findings,
    }


class ReportExportHackerOneTests(unittest.TestCase):
    def test_confirmed_finding_produces_submission_headers(self):
        body = render_report(_scan([_finding()]), "hackerone")
        self.assertIn("## [Medium] Missing content-security-policy", body)
        self.assertIn("### Summary", body)
        self.assertIn("### Steps to Reproduce", body)
        self.assertIn("1. Send GET / with an authorized test session.", body)
        self.assertIn("3. Confirm the content-security-policy header is absent.", body)
        self.assertIn("### Supporting Evidence", body)
        self.assertIn("Add the content-security-policy response header.", body)

    def test_artifact_path_included_in_output(self):
        body = render_report(_scan([_finding()]), "hackerone")
        self.assertIn("evidence/scan/header-csp.json", body)
        self.assertIn("Evidence artifact: evidence/scan/header-csp.json", body)

    def test_marketplace_report_groups_repeated_confirmed_issue_by_affected_urls(self):
        first = _finding()
        second = _finding()
        second["id"] = "finding-2"
        second["url"] = "https://example.com/account"
        second["evidence_artifact"] = {
            **second["evidence_artifact"],
            "artifact_path": "evidence/scan/header-csp-account.json",
        }
        scan = _scan([first, second])
        scan["analysis"] = {
            "zero_fp_gate": {
                "valid_bugs": [first, second],
                "needs_more_proof": [],
                "candidates": [],
                "informational": [],
                "false_positives_removed": [],
                "skipped_out_of_scope": [],
            }
        }

        body = render_report(scan, "hackerone")

        self.assertEqual(body.count("## [Medium] Missing content-security-policy"), 1)
        self.assertIn("### Affected URLs", body)
        self.assertIn("- https://example.com", body)
        self.assertIn("- https://example.com/account", body)
        self.assertIn("Additional artifacts:", body)
        self.assertIn("evidence/scan/header-csp-account.json", body)

    def test_readiness_report_summarizes_ready_and_manual_check_work(self):
        ready_one = _finding()
        ready_two = _finding()
        ready_two["id"] = "finding-2"
        ready_two["url"] = "https://example.com/account"
        manual = _finding("candidate", "SSRF-prone parameter observed")
        manual["zero_fp_failed_checks"] = ["exploitability_not_confirmed_or_probable"]
        scan = _scan([ready_one, ready_two, manual])
        scan["analysis"] = {
            "zero_fp_gate": {
                "valid_bugs": [ready_one, ready_two],
                "needs_more_proof": [manual],
                "candidates": [],
                "informational": [],
                "false_positives_removed": [{"title": "Duplicate"}],
                "skipped_out_of_scope": [],
            }
        }

        body = render_report(scan, "readiness")

        self.assertIn("# Bounty Readiness Audit", body)
        self.assertIn("- Report-ready issues: 1", body)
        self.assertIn("- Report-ready findings: 2", body)
        self.assertIn("- Manual-check findings: 1", body)
        self.assertIn("- Removed/out-of-scope findings: 1", body)
        self.assertIn("- Grouped findings: 2", body)
        self.assertIn("SSRF-prone parameter observed", body)
        self.assertIn("exploitability_not_confirmed_or_probable", body)
        self.assertIn("Safe validation steps:", body)
        self.assertIn("1. Validate only within authorized scope.", body)

    def test_candidates_section_lists_unconfirmed_findings(self):
        candidate = _finding("needs_manual_validation", "Open redirect candidate parameter observed")
        candidate["confidence"] = 70
        candidate["zero_fp_failed_checks"] = ["exploitability_not_confirmed_or_probable"]
        body = render_report(_scan([_finding(), candidate]), "hackerone")
        self.assertIn("## Candidates Requiring Manual Validation", body)
        self.assertIn("Open redirect candidate parameter observed", body)
        self.assertIn("Confidence: 70", body)
        self.assertIn("Artifact: evidence/scan/header-csp.json (missing)", body)
        self.assertIn("Why not report-ready: exploitability_not_confirmed_or_probable", body)
        self.assertIn("Safe manual validation:", body)
        self.assertIn("1. Validate only within authorized scope.", body)
        self.assertEqual(body.count("### Summary"), 1)

    def test_marketplace_report_uses_proof_gated_buckets_when_available(self):
        blocked = _finding("confirmed", "SQL Injection without artifact proof")
        scan = _scan([blocked])
        scan["confirmed_findings"] = []
        scan["candidate_findings"] = [blocked]
        body = render_report(scan, "hackerone")
        self.assertIn("No confirmed findings are ready for submission.", body)
        self.assertIn("## Candidates Requiring Manual Validation", body)
        self.assertIn("SQL Injection without artifact proof", body)
        self.assertNotIn("## [Medium] SQL Injection without artifact proof", body)

    def test_marketplace_report_uses_analysis_zero_fp_gate_when_top_level_buckets_absent(self):
        ready = _finding("confirmed", "Report-ready header finding")
        ready["zero_fp_label"] = "READY"
        blocked = _finding("confirmed", "Manual-check header finding")
        blocked["zero_fp_label"] = "NEEDS PROOF"
        scan = _scan([ready, blocked])
        scan["analysis"] = {
            "zero_fp_gate": {
                "valid_bugs": [ready],
                "needs_more_proof": [blocked],
                "candidates": [],
                "informational": [],
                "false_positives_removed": [],
                "skipped_out_of_scope": [],
            }
        }
        body = render_report(scan, "hackerone")
        self.assertIn("## [Medium] Report-ready header finding", body)
        self.assertIn("## Candidates Requiring Manual Validation", body)
        self.assertIn("Manual-check header finding", body)
        self.assertNotIn("## [Medium] Manual-check header finding", body)

    def test_full_report_uses_zero_fp_valid_bugs_when_available(self):
        blocked = _finding("confirmed", "Confirmed-looking finding blocked by proof gate")
        blocked["verdict"] = "PASS"
        report = asyncio.run(generate_full_report(
            "https://example.com",
            {"stats": {}},
            [blocked],
            {
                "zero_fp_gate": {
                    "valid_bugs": [],
                    "needs_more_proof": [blocked],
                    "candidates": [],
                    "informational": [],
                    "false_positives_removed": [],
                    "skipped_out_of_scope": [],
                }
            },
            scope={"allowed_domains": ["example.com"]},
        ))
        self.assertIn("| **Total Findings** | 0 |", report)
        self.assertNotIn("Confirmed-looking finding blocked by proof gate", report)

    def test_json_csv_and_sarif_respect_zero_fp_buckets(self):
        ready = _finding("confirmed", "Report-ready SQL injection")
        ready["zero_fp_label"] = "READY"
        blocked = _finding("confirmed", "Blocked confirmed-looking finding")
        blocked["zero_fp_label"] = "NEEDS PROOF"
        blocked["ready_to_submit"] = True
        scan = _scan([ready, blocked])
        scan["analysis"] = {
            "zero_fp_gate": {
                "valid_bugs": [ready],
                "needs_more_proof": [blocked],
                "candidates": [],
                "informational": [],
                "false_positives_removed": [],
                "skipped_out_of_scope": [],
            }
        }

        json_report = json.loads(render_report(scan, "json"))
        self.assertEqual(
            [item["title"] for item in json_report["confirmed_findings"]],
            ["Report-ready SQL injection"],
        )
        self.assertEqual(
            [item["title"] for item in json_report["candidate_findings"]],
            ["Blocked confirmed-looking finding"],
        )

        csv_report = render_report(scan, "csv")
        self.assertIn("Report-ready SQL injection", csv_report)
        self.assertIn("Blocked confirmed-looking finding", csv_report)
        self.assertIn("READY", csv_report)
        self.assertIn("NEEDS PROOF", csv_report)

        sarif = json.loads(render_report(scan, "sarif"))
        messages = [
            result["message"]["text"]
            for result in sarif["runs"][0]["results"]
        ]
        self.assertTrue(any("Report-ready SQL injection" in item for item in messages))
        self.assertFalse(any("Blocked confirmed-looking finding" in item for item in messages))

    def test_empty_scan_has_graceful_message(self):
        body = render_report(_scan([]), "hackerone")
        self.assertIn("No confirmed findings are ready for submission.", body)

    def test_bugcrowd_uses_same_submission_structure(self):
        hackerone = render_report(_scan([_finding()]), "hackerone")
        bugcrowd = render_report(_scan([_finding()]), "bugcrowd")
        self.assertIn("## [Medium] Missing content-security-policy", bugcrowd)
        self.assertIn("### Steps to Reproduce", bugcrowd)
        self.assertEqual(
            hackerone.replace("HackerOne", "Bugcrowd"),
            bugcrowd,
        )

    def test_bundle_writes_requested_marketplace_filenames(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = write_report_bundle(
                _scan([_finding()]),
                temp,
                formats=("hackerone", "bugcrowd"),
            )
            self.assertTrue(paths["hackerone"].endswith("hackerone-report.md"))
            self.assertTrue(paths["bugcrowd"].endswith("bugcrowd-report.md"))
            self.assertTrue(Path(paths["hackerone"]).exists())

    def test_default_bundle_writes_readiness_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = write_report_bundle(_scan([_finding()]), temp)
            self.assertTrue(paths["readiness"].endswith("readiness-audit.md"))
            body = Path(paths["readiness"]).read_text()
            self.assertIn("# Bounty Readiness Audit", body)

    def test_cli_hackerone_format_writes_default_report_path(self):
        with tempfile.TemporaryDirectory() as temp:
            scan = _scan([_finding()])
            with patch.object(cli, "scan_store") as store, patch.object(cli, "Path", lambda value: Path(temp) / value):
                store.get.return_value = scan
                code = __import__("asyncio").run(cli.command_report(Namespace(
                    scan_id="scan-h1",
                    format="hackerone",
                    output=None,
                )))
            self.assertEqual(code, 0)
            self.assertTrue((Path(temp) / "reports" / "scan-h1" / "hackerone-report.md").exists())


if __name__ == "__main__":
    unittest.main()
