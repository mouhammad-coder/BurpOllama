import asyncio
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console

import cli
from core.program_profile import load_program_profile


def write_program(directory: str, body: str) -> str:
    path = Path(directory) / "program.yml"
    path.write_text(body, encoding="utf-8")
    return str(path)


class FakeScanner:
    def __init__(self):
        self.prepared = None

    def prepare(self, target, mode, **kwargs):
        self.prepared = {"target": target, "mode": mode, **kwargs}
        return {
            "id": "scan-auto",
            "target": target,
            "mode": mode,
            "goal": kwargs.get("goal"),
            "program_profile": kwargs.get("program_profile", {}),
            "automated_scanning_allowed": kwargs.get("program_profile", {}).get("automated_scanning_allowed", "unknown"),
            "options": {"output": kwargs.get("output", "scans")},
            "recon": {"urls": [target]},
            "agent_status": {"recon": {}, "proof": {}, "final-findings-presenter": {}},
        }

    async def run_prepared(self, prepared, **_kwargs):
        prepared["status"] = "complete"
        prepared["artifact_paths"] = {"findings.json": str(Path("scans") / prepared["id"] / "findings.json")}
        prepared["final_findings"] = {
            "great": [],
            "manual": [{
                "id": "F-1",
                "title": "Possible BOLA on /api/orders/{id}",
                "status": "Needs Manual Check",
                "rate": "High",
                "confidence": 72,
                "affected_asset": "api.example.com",
                "evidence": "Object ID endpoint found",
                "why_it_matters": "Possible unauthorized order access",
                "next_step": "Test with two authorized accounts.",
                "missing_proof": "No second-user comparison",
                "manual_check_needed": "Test with two authorized accounts.",
            }],
            "informational": [],
            "rejected": [{"id": "R-1", "status": "Rejected"}],
            "all": [],
            "counts": {"great": 0, "manual": 1, "informational": 0, "rejected": 1},
        }
        return prepared


class AutopilotGoalTests(unittest.TestCase):
    def test_supported_goal_and_final_output_options_parse(self):
        parser = cli.build_parser()
        preflight = parser.parse_args(["preflight", "https://example.com", "--program", "program.yml"])
        self.assertEqual(preflight.command, "preflight")
        dry_run = parser.parse_args(["ai-autopilot", "https://example.com", "--dry-run-plan"])
        self.assertTrue(dry_run.dry_run_plan)
        for goal in (
            "recon",
            "bounty-hunt",
            "access-control",
            "api-hunt",
            "passive-analysis",
            "manual-check",
            "burp-import-analysis",
        ):
            args = parser.parse_args([
                "ai-autopilot",
                "https://example.com",
                "--goal",
                goal,
                "--final-output",
                "chat",
            ])
            self.assertEqual(args.goal, goal)
            self.assertEqual(args.final_output, "chat")

    def test_program_profile_parses_scanner_permission_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
platform: hackerone
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
  - api.example.com
out_of_scope:
  - staging.example.com
forbidden_tests:
  - dos
  - brute_force
allowed_modes:
  - passive
  - bounty
max_rps: 2
max_concurrency: 5
auth_testing_allowed: true
upload_testing_allowed: false
graphql_introspection_allowed: false
oob_testing_allowed: false
cloud_ai_allowed: false
""")
            profile = load_program_profile(program)
        self.assertEqual(profile.scanner_permission_label, "yes")
        self.assertEqual(profile.max_rps, 2)
        self.assertFalse(profile.upload_testing_allowed)
        self.assertFalse(profile.graphql_introspection_allowed)
        self.assertTrue(profile.target_allowed("https://api.example.com")[0])
        self.assertFalse(profile.target_allowed("https://staging.example.com")[0])

    def test_invalid_program_yml_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: bad
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - "bad host name"
max_rps: -1
max_concurrency: 0
allowed_modes:
  - waf_bypass
""")
            with self.assertRaises(ValueError):
                load_program_profile(program)

    def test_no_program_requires_yes_and_scope(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=140)
        args = SimpleNamespace(
            target="https://example.com",
            from_burp="",
            program=None,
            goal="bounty-hunt",
            mode="passive",
            final_output="terminal",
            yes=False,
            scope=None,
        )
        with patch.object(cli, "console", console):
            code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 2)
        self.assertIn("I confirm I am authorized", stream.getvalue())

    def test_scanner_allowed_missing_defaults_to_passive_and_prints_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
in_scope:
  - example.com
max_rps: 1
max_concurrency: 2
""")
            fake = FakeScanner()
            stream = io.StringIO()
            console = Console(file=stream, force_terminal=False, width=160)
            args = SimpleNamespace(
                target="https://example.com",
                from_burp="",
                program=program,
                goal="bounty-hunt",
                mode="bounty",
                multi_agent=True,
                final_output="terminal",
                yes=False,
                scope=None,
                scope_file=None,
                auth_profile=None,
                concurrency=10,
                rate_limit=10,
                timeout=5,
                retries=0,
                time_budget=60,
                max_urls=10,
                ai=False,
                no_ai=True,
                ai_provider="",
                model="",
                output=str(Path(temp) / "scans"),
                no_external_tools=True,
                oob_server="",
            )
            with patch.object(cli, "scanner", fake), patch.object(cli, "console", console):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        self.assertEqual(fake.prepared["mode"], "passive")
        self.assertEqual(fake.prepared["rate_limit"], 1)
        self.assertEqual(fake.prepared["concurrency"], 2)
        self.assertIn("Automated scanner permission is unknown", stream.getvalue())
        self.assertIn("Scan Finished", stream.getvalue())
        self.assertIn("Needs Manual Check", stream.getvalue())

    def test_dry_run_plan_does_not_prepare_scanner(self):
        class FailingScanner:
            def prepare(self, *args, **kwargs):
                raise AssertionError("dry-run should not prepare scanner")

        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
allowed_modes:
  - passive
  - bounty
auth_testing_allowed: false
upload_testing_allowed: false
cloud_ai_allowed: false
""")
            stream = io.StringIO()
            args = SimpleNamespace(
                target="https://example.com",
                from_burp="",
                program=program,
                goal="bounty-hunt",
                mode="bounty",
                dry_run_plan=True,
                rate_limit=10,
                concurrency=10,
                yes=False,
                scope=None,
            )
            with patch.object(cli, "scanner", FailingScanner()), patch.object(cli, "console", Console(file=stream, force_terminal=False, width=160)):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        self.assertIn("Dry Run Plan", stream.getvalue())
        self.assertIn("Checks blocked", stream.getvalue())

    def test_preflight_output_includes_release_readiness_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
allowed_modes:
  - passive
  - bounty
max_rps: 2
max_concurrency: 5
auth_testing_allowed: true
upload_testing_allowed: false
oob_testing_allowed: false
cloud_ai_allowed: false
""")
            stream = io.StringIO()
            args = SimpleNamespace(
                target="https://example.com",
                program=program,
                goal="bounty-hunt",
                mode="bounty",
            )
            with (
                patch.object(cli, "console", Console(file=stream, force_terminal=False, width=180)),
                patch.object(cli, "_resolve_target_host", return_value=(True, "resolves")),
            ):
                code = asyncio.run(cli.command_preflight(args))
        output = stream.getvalue()
        self.assertEqual(code, 0)
        for text in (
            "Target",
            "In scope",
            "Scanner allowed",
            "Automated testing allowed",
            "Mode allowed",
            "Effective mode",
            "Max RPS",
            "Max concurrency",
            "Cloud AI allowed",
            "Auth testing allowed",
            "Upload testing allowed",
            "OOB allowed",
            "Blocked checks",
            "Recommended safe command",
        ):
            self.assertIn(text, output)

    def test_automated_testing_allowed_missing_defaults_to_passive(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
scanner_allowed: true
in_scope:
  - example.com
allowed_modes:
  - passive
  - bounty
""")
            fake = FakeScanner()
            stream = io.StringIO()
            args = SimpleNamespace(
                target="https://example.com",
                from_burp="",
                program=program,
                goal="bounty-hunt",
                mode="bounty",
                multi_agent=True,
                final_output="terminal",
                yes=False,
                scope=None,
                scope_file=None,
                auth_profile=None,
                concurrency=5,
                rate_limit=2,
                timeout=5,
                retries=0,
                time_budget=60,
                max_urls=10,
                ai=False,
                no_ai=True,
                ai_provider="",
                model="",
                output=str(Path(temp) / "scans"),
                no_external_tools=True,
                oob_server="",
            )
            with patch.object(cli, "scanner", fake), patch.object(cli, "console", Console(file=stream, force_terminal=False, width=160)):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        self.assertEqual(fake.prepared["mode"], "passive")
        self.assertEqual(fake.prepared["program_profile"]["automated_scanning_allowed"], "unknown")
        self.assertIn("Automated scanner permission is unknown", stream.getvalue())

    def test_final_output_json_is_valid_stdout_json(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
allowed_modes:
  - passive
  - bounty
""")
            fake = FakeScanner()
            stream = io.StringIO()
            args = SimpleNamespace(
                target="https://example.com",
                from_burp="",
                program=program,
                goal="bounty-hunt",
                mode="passive",
                multi_agent=True,
                final_output="json",
                yes=False,
                scope=None,
                scope_file=None,
                auth_profile=None,
                concurrency=5,
                rate_limit=2,
                timeout=5,
                retries=0,
                time_budget=60,
                max_urls=10,
                ai=False,
                no_ai=True,
                ai_provider="",
                model="",
                output=str(Path(temp) / "scans"),
                no_external_tools=True,
                oob_server="",
            )
            with patch.object(cli, "scanner", fake), patch.object(cli, "console", Console(file=stream, force_terminal=False)):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["goal"], "bounty-hunt")
        self.assertEqual(payload["automated_scanning_allowed"], "yes")
        self.assertEqual(payload["findings"]["counts"]["manual"], 1)

    def test_scanner_allowed_false_prevents_active_scanning(self):
        with tempfile.TemporaryDirectory() as temp:
            program = write_program(temp, """
program: example
scanner_allowed: false
automated_testing_allowed: false
in_scope:
  - example.com
allowed_modes:
  - passive
  - bounty
cloud_ai_allowed: false
""")
            fake = FakeScanner()
            stream = io.StringIO()
            args = SimpleNamespace(
                target="https://example.com",
                from_burp="",
                program=program,
                goal="bounty-hunt",
                mode="bounty",
                multi_agent=True,
                final_output="chat",
                yes=False,
                scope=None,
                scope_file=None,
                auth_profile=None,
                concurrency=5,
                rate_limit=2,
                timeout=5,
                retries=0,
                time_budget=60,
                max_urls=10,
                ai=True,
                no_ai=False,
                ai_provider="",
                model="",
                output=str(Path(temp) / "scans"),
                no_external_tools=True,
                oob_server="",
            )
            with patch.object(cli, "scanner", fake), patch.object(cli, "console", Console(file=stream, force_terminal=False, width=160)):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        self.assertEqual(fake.prepared["mode"], "passive")
        self.assertFalse(fake.prepared["ai_enabled"])
        self.assertEqual(fake.prepared["program_profile"]["automated_scanning_allowed"], "no")
        self.assertIn("Active scanning disabled", stream.getvalue())
        self.assertIn("Scan Finished", stream.getvalue())

    def test_burp_import_records_latest_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "burp-history.xml"
            source.write_text("<items></items>", encoding="utf-8")
            program = write_program(temp, "program: example\nin_scope:\n  - example.com\n")
            import_dir = Path(temp) / "imports"
            stream = io.StringIO()
            args = SimpleNamespace(burp_command="import", file=str(source), program=program)
            with patch.object(cli, "BURP_IMPORT_DIR", import_dir), patch.object(cli, "console", Console(file=stream, force_terminal=False)):
                code = asyncio.run(cli.command_burp(args))
            payload = json.loads((import_dir / "latest.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(payload["path"], str(source))
        self.assertEqual(payload["target"], "https://example.com")
        self.assertTrue(payload["no_replay"])
        self.assertIn("metadata", payload)
        self.assertIn("ai-autopilot --from-burp latest", stream.getvalue())

    def test_burp_import_analysis_uses_offline_import_not_live_scanner(self):
        class FailingScanner:
            def prepare(self, *args, **kwargs):
                raise AssertionError("live scanner should not run for burp-import-analysis")

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "burp-history.xml"
            source.write_text(
                "<url>https://example.com/api/orders/1</url>\n"
                "<url>https://evil.example.net/out</url>",
                encoding="utf-8",
            )
            program = write_program(temp, """
program: example
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
""")
            import_dir = Path(temp) / "imports"
            import_args = SimpleNamespace(burp_command="import", file=str(source), program=program)
            with patch.object(cli, "BURP_IMPORT_DIR", import_dir), patch.object(cli, "console", Console(file=io.StringIO(), force_terminal=False)):
                asyncio.run(cli.command_burp(import_args))
            stream = io.StringIO()
            args = SimpleNamespace(
                target="",
                from_burp="latest",
                program=program,
                goal="burp-import-analysis",
                mode="bounty",
                multi_agent=True,
                final_output="chat",
                yes=False,
                scope=None,
                scope_file=None,
                auth_profile=None,
                concurrency=5,
                rate_limit=2,
                timeout=5,
                retries=0,
                time_budget=60,
                max_urls=10,
                ai=False,
                no_ai=True,
                ai_provider="",
                model="",
                output=str(Path(temp) / "scans"),
                no_external_tools=True,
                oob_server="",
            )
            with (
                patch.object(cli, "BURP_IMPORT_DIR", import_dir),
                patch.object(cli, "scanner", FailingScanner()),
                patch.object(cli, "console", Console(file=stream, force_terminal=False, width=160)),
            ):
                code = asyncio.run(cli.command_ai_autopilot(args))
        self.assertEqual(code, 0)
        output = stream.getvalue()
        self.assertIn("Scan Finished", output)
        self.assertIn("Goal: burp-import-analysis", output)
        self.assertIn("URLs Checked: 1", output)

    def test_burp_import_dedupes_and_generates_manual_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "burp-history.xml"
            source.write_text(
                "<items><item><url>https://example.com/api/orders/1/?b=2&a=1&a=3</url></item>"
                "<item><url>https://example.com/api/orders/1?a=1&b=2</url></item>"
                "<item><url>https://example.com/upload</url></item></items>",
                encoding="utf-8",
            )
            urls = cli._urls_from_burp_file(str(source), ["example.com"])
            self.assertEqual(len(urls), 2)
            findings = cli._burp_passive_findings(urls, {"path": str(source)})
            self.assertTrue(any("IDOR" in item["title"] for item in findings))
            self.assertTrue(any("Upload" in item["title"] for item in findings))

    def test_auth_profile_parsing_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "userA.json"
            profile.write_text(json.dumps({
                "name": "userA",
                "base_url": "https://example.com",
                "cookies": {"session_id": "abcdef1234567890"},
                "headers": {"Authorization": "Bearer abcdef1234567890"},
                "role": "user",
                "notes": "owned test account",
            }), encoding="utf-8")
            loaded = cli._load_auth_profiles([str(profile)])
        rendered = json.dumps(loaded)
        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("abcdef1234567890", rendered)


if __name__ == "__main__":
    unittest.main()
