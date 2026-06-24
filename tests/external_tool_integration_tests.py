from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import cli
from core.integrations.gitleaks import scan_js_content as scan_gitleaks
from core.integrations.katana import run_katana
from core.integrations.nuclei import run_nuclei
from core.integrations.tool_checker import check_tool
from core.integrations.trufflehog import scan_js_content as scan_trufflehog
from core.scanner import ScanOptions, Scanner


class _Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _Scope:
    def allows(self, url):
        return "example.com" in str(url)


class ExternalToolIntegrationTests(unittest.TestCase):
    def test_tool_checker_returns_false_for_missing_tool(self):
        with patch("core.integrations.tool_checker.shutil.which", return_value=None):
            self.assertFalse(check_tool("missing-tool"))

    def test_katana_wrapper_filters_out_of_scope_urls(self):
        stdout = "https://example.com/a\nhttps://evil.test/b\nhttps://sub.example.com/c\n"
        with tempfile.TemporaryDirectory() as temp, patch(
            "core.integrations.katana.check_tool",
            return_value=True,
        ), patch(
            "core.integrations.katana.subprocess.run",
            return_value=_Completed(stdout=stdout),
        ):
            urls = run_katana("https://example.com", _Scope(), temp)
        self.assertEqual(urls, ["https://example.com/a", "https://sub.example.com/c"])

    def test_nuclei_output_parsed_into_candidate_finding(self):
        item = {
            "template-id": "exposed-panel",
            "matched-at": "https://example.com/admin",
            "info": {"name": "Exposed Admin Panel", "severity": "high"},
        }
        with tempfile.TemporaryDirectory() as temp, patch(
            "core.integrations.nuclei.check_tool",
            return_value=True,
        ), patch(
            "core.integrations.nuclei.subprocess.run",
            return_value=_Completed(stdout=json.dumps(item)),
        ):
            findings = run_nuclei(
                "https://example.com",
                temp,
                scan={"id": "nuclei-test"},
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["exploitability_status"], "candidate")
        self.assertTrue(Path(findings[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_trufflehog_hit_produces_redacted_artifact(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        payload = {
            "DetectorName": "AWS",
            "Raw": secret,
            "Line": 7,
            "Verified": False,
        }
        with patch("core.integrations.trufflehog.check_tool", return_value=True), patch(
            "core.integrations.trufflehog.subprocess.run",
            return_value=_Completed(stdout=json.dumps(payload) + "\n"),
        ):
            findings = scan_trufflehog("const key='{}';".format(secret), "truffle-test", "https://example.com/app.js")
        self.assertEqual(len(findings), 1)
        artifact_text = Path(findings[0]["evidence_artifact"]["artifact_path"]).read_text(encoding="utf-8")
        self.assertNotIn(secret, artifact_text)
        self.assertIn("REDACTED-AWS-", artifact_text)
        self.assertEqual(findings[0]["exploitability_status"], "needs_manual_validation")

    def test_gitleaks_hit_produces_redacted_artifact(self):
        secret = "ghp_exampleSecretToken123"
        payload = [{
            "RuleID": "github-pat",
            "Secret": secret,
            "StartLine": 3,
            "Entropy": 4.2,
        }]
        with patch("core.integrations.gitleaks.check_tool", return_value=True), patch(
            "core.integrations.gitleaks.subprocess.run",
            return_value=_Completed(stdout=json.dumps(payload)),
        ):
            findings = scan_gitleaks("const token='{}';".format(secret), "gitleaks-test", "https://example.com/app.js")
        self.assertEqual(len(findings), 1)
        artifact_text = Path(findings[0]["evidence_artifact"]["artifact_path"]).read_text(encoding="utf-8")
        self.assertNotIn(secret, artifact_text)
        self.assertIn("REDACTED-github-pat-", artifact_text)

    def test_passive_mode_skips_nuclei_and_secret_scanners(self):
        scanner = Scanner()
        called = {"nuclei": 0, "secrets": 0}

        class _Agent:
            async def execute(self, context):
                context.recon.setdefault("urls", [context.scan["target"]])
                context.recon.setdefault("js_contents", {"https://example.com/app.js": "const x=1;"})

        class _Scheduler:
            async def run(self, _name, operation):
                return await operation()

            def state(self, _name):
                return SimpleNamespace(findings=0, last_event="", status="pending")

        async def fake_katana(_context):
            return None

        async def fake_nuclei(_context):
            called["nuclei"] += 1

        async def fake_secrets(_context):
            called["secrets"] += 1

        context = SimpleNamespace(
            scan={"id": "passive-skip", "target": "https://example.com", "ai": {}},
            options=ScanOptions(mode="passive"),
            recon={},
            scheduler=_Scheduler(),
        )
        with patch("core.scanner.ReconAgent", _Agent), patch("core.scanner.CrawlerAgent", _Agent), patch("core.scanner.JavaScriptAgent", _Agent):
            scanner._external_katana = fake_katana
            scanner._external_nuclei = fake_nuclei
            scanner._external_js_secret_scans = fake_secrets
            asyncio.run(scanner._recon(context))
        self.assertEqual(called, {"nuclei": 0, "secrets": 0})

    def test_no_external_tools_flag_disables_scan_option(self):
        parser = cli.build_parser()
        args = parser.parse_args([
            "scan",
            "https://example.com",
            "--no-external-tools",
        ])
        self.assertTrue(args.no_external_tools)
        self.assertTrue(ScanOptions(no_external_tools=True).no_external_tools)

    def test_missing_tool_skips_without_crash(self):
        with tempfile.TemporaryDirectory() as temp, patch(
            "core.integrations.katana.check_tool",
            return_value=False,
        ):
            self.assertEqual(run_katana("https://example.com", _Scope(), temp), [])


if __name__ == "__main__":
    unittest.main()
