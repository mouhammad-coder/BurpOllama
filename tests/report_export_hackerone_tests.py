from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import cli
from core.reports import render_report, write_report_bundle


def _finding(status="confirmed", title="Missing content-security-policy"):
    return {
        "id": "finding-1",
        "title": title,
        "vuln_type": "Missing Security Headers",
        "severity": "MEDIUM",
        "confidence": 94,
        "url": "https://example.com",
        "exploitability_status": status,
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
        self.assertIn("### Supporting Evidence", body)
        self.assertIn("Add the content-security-policy response header.", body)

    def test_artifact_path_included_in_output(self):
        body = render_report(_scan([_finding()]), "hackerone")
        self.assertIn("evidence/scan/header-csp.json", body)
        self.assertIn("Evidence artifact: evidence/scan/header-csp.json", body)

    def test_candidates_section_lists_unconfirmed_findings(self):
        candidate = _finding("needs_manual_validation", "Open redirect candidate parameter observed")
        candidate["confidence"] = 70
        body = render_report(_scan([_finding(), candidate]), "hackerone")
        self.assertIn("## Candidates Requiring Manual Validation", body)
        self.assertIn("Open redirect candidate parameter observed", body)
        self.assertIn("Confidence: 70", body)
        self.assertEqual(body.count("### Summary"), 1)

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
