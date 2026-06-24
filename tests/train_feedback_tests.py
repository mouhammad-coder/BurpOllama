from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import cli


def _finding(status="confirmed"):
    return {
        "id": "finding-1",
        "vulnerability_class": "JWT Algorithm None Observation",
        "title": "JWT uses alg=none",
        "severity": "MEDIUM",
        "exploitability_status": status,
        "url": "https://example.com/private",
        "evidence_artifact": {
            "matched_indicator": "alg=none",
            "indicator_location": "response header authorization",
            "raw_request": "GET /private HTTP/1.1",
            "raw_response": "HTTP/1.1 200 OK",
            "url": "https://example.com/private",
        },
        "ai_triage": {
            "exploitability": "medium",
            "false_positive_risk": "low",
            "triage_note": "Review token configuration.",
        },
    }


class _Store:
    def __init__(self, scan):
        self.scan = scan

    def get(self, scan_id):
        return self.scan if scan_id == self.scan["id"] else None


class TrainFeedbackTests(unittest.TestCase):
    def setUp(self):
        self._tempdirs = []

    def _run_train(self, verdict_key, finding=None):
        temp = tempfile.TemporaryDirectory()
        self._tempdirs.append(temp)
        self.addCleanup(temp.cleanup)
        feedback = Path(temp.name) / "data" / "feedback.jsonl"
        scan = {
            "id": "scan-1",
            "confirmed_findings": [finding or _finding()],
            "candidate_findings": [],
        }
        args = Namespace(command="train", scan_id="scan-1", stats=False)
        with patch.object(cli, "FEEDBACK_PATH", feedback), patch.object(
            cli, "scan_store", _Store(scan)
        ), patch.object(cli.console, "input", return_value=verdict_key):
            code = asyncio.run(cli.command_train(args))
        return code, feedback

    def test_valid_verdict_appends_correct_record_schema(self):
        code, feedback = self._run_train("v")
        self.assertEqual(code, 0)
        record = json.loads(feedback.read_text(encoding="utf-8").strip())
        self.assertEqual(set(record), {
            "scan_id",
            "vuln_class",
            "matched_indicator",
            "indicator_location",
            "ai_exploitability",
            "ai_fp_risk",
            "human_verdict",
            "timestamp",
        })
        self.assertEqual(record["human_verdict"], "valid")
        self.assertEqual(record["scan_id"], "scan-1")
        self.assertEqual(record["matched_indicator"], "alg=none")

    def test_fp_verdict_appends_correctly(self):
        code, feedback = self._run_train("f")
        self.assertEqual(code, 0)
        record = json.loads(feedback.read_text(encoding="utf-8").strip())
        self.assertEqual(record["human_verdict"], "false_positive")
        self.assertEqual(record["ai_fp_risk"], "low")

    def test_skip_leaves_file_unchanged(self):
        code, feedback = self._run_train("s")
        self.assertEqual(code, 0)
        self.assertFalse(feedback.exists())

    def test_raw_request_response_and_url_never_written(self):
        code, feedback = self._run_train("v")
        self.assertEqual(code, 0)
        text = feedback.read_text(encoding="utf-8")
        self.assertNotIn("raw_request", text)
        self.assertNotIn("raw_response", text)
        self.assertNotIn("https://example.com/private", text)
        self.assertNotIn("GET /private", text)
        self.assertNotIn("HTTP/1.1 200 OK", text)

    def test_stats_command_handles_empty_feedback_file(self):
        with tempfile.TemporaryDirectory() as temp:
            feedback = Path(temp) / "data" / "feedback.jsonl"
            args = SimpleNamespace(command="train", scan_id=None, stats=True)
            with patch.object(cli, "FEEDBACK_PATH", feedback):
                code = asyncio.run(cli.command_train(args))
            self.assertEqual(code, 0)
            self.assertEqual(cli._feedback_stats(feedback)["total"], 0)


if __name__ == "__main__":
    unittest.main()
