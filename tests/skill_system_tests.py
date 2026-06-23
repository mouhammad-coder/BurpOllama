from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.skills.evidence import validate_evidence_schema
from core.skills.knowledge_base import SkillKnowledgeBase
from core.skills.loader import SkillLoader
from core.skills.registry import SkillRegistry
from core.skills.runner import SkillRunOptions, SkillRunner, SkillSafetyError
from core.skills.validator import SkillValidator


class SkillSystemTests(unittest.TestCase):
    def test_loader_loads_extracted_subdomain_takeover_skill(self):
        skill = SkillLoader().load("subdomain-takeover-hunter")
        self.assertEqual(skill.name, "subdomain-takeover-hunter")
        self.assertIn("takeover", skill.description.lower())
        self.assertIn("references/safety.md", skill.references)

    def test_validator_detects_required_files(self):
        result = SkillValidator().validate("subdomain-takeover-hunter")
        self.assertTrue(result.valid, result.errors)
        self.assertIn("references/proof.md", result.files)
        self.assertIn(
            "references/real_reports.json",
            SkillLoader().load("subdomain-takeover-hunter").references,
        )

    def test_registry_list_shows_subdomain_takeover_hunter(self):
        names = [skill.name for skill in SkillRegistry().list()]
        self.assertIn("subdomain-takeover-hunter", names)

    def test_refresh_knowledge_includes_real_report_corpus(self):
        with tempfile.TemporaryDirectory() as temp:
            kb = SkillKnowledgeBase(temp)
            path = kb.refresh("subdomain-takeover-hunter")
            data = json.loads(path.read_text(encoding="utf-8"))
        corpus = data.get("real_report_corpus", {})
        self.assertGreaterEqual(
            corpus.get("counts", {}).get("detailed_cases", 0),
            100,
        )
        self.assertTrue(corpus.get("top_services"))
        self.assertTrue(corpus.get("curated_resources"))

    def test_cli_skills_list_and_show_work(self):
        import cli

        self.assertEqual(cli.main(["skills", "list"]), 0)
        self.assertEqual(
            cli.main(["skills", "show", "subdomain-takeover-hunter"]),
            0,
        )

    def test_malformed_skill_does_not_crash_validator(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bad = root / "broken"
            bad.mkdir()
            (bad / "SKILL.md").write_text("---\nname: broken\n", encoding="utf-8")
            result = SkillValidator(root).validate("broken")
        self.assertFalse(result.valid)
        self.assertTrue(result.errors)

    def test_unauthorized_target_is_refused(self):
        skill = SkillLoader().load("subdomain-takeover-hunter")
        with self.assertRaises(SkillSafetyError):
            SkillRunner().safety_gate(
                skill,
                SkillRunOptions(
                    target="example.com",
                    authorization_confirmed=False,
                    scope_confirmed=True,
                ),
            )

    def test_proof_of_control_disabled_by_default(self):
        options = SkillRunOptions(
            target="example.com",
            authorization_confirmed=True,
            scope_confirmed=True,
        )
        self.assertFalse(options.proof_of_control_allowed)
        self.assertFalse(options.proof_of_control_confirmed)

    def test_evidence_artifact_schema_is_valid(self):
        record = {
            "target_subdomain": "sub.example.com",
            "root_domain": "example.com",
            "scope_status": "in_scope",
            "discovery_source": "unit-test",
            "dns_evidence": {},
            "http_evidence": {},
            "tls_evidence": {},
            "provider_fingerprint": {},
            "false_positive_checks": [],
            "proof_of_control_allowed": False,
            "proof_performed": False,
            "reproduction_commands": [],
            "timestamp": "2026-06-24T00:00:00Z",
            "final_status": "Needs Confirmation",
        }
        valid, missing = validate_evidence_schema(record)
        self.assertTrue(valid)
        self.assertEqual(missing, [])

    def test_normal_scanner_path_does_not_run_skills(self):
        import core.scanner as scanner_module

        async def fake_phase(_self, _context, _phase_name, _operation):
            return None

        with patch.object(scanner_module.Scanner, "_phase", fake_phase):
            with patch("core.skills.runner.SkillRunner.run") as skill_run:
                scan = asyncio.run(
                    scanner_module.Scanner().run(
                        "https://example.com",
                        "passive",
                        authorization_confirmed=True,
                        ai_enabled=False,
                        output=tempfile.gettempdir(),
                    )
                )
        self.assertFalse(skill_run.called)
        self.assertEqual(scan.get("status"), "complete")

    def test_runner_writes_safe_evidence_without_proof(self):
        skill = SkillLoader().load("subdomain-takeover-hunter")

        async def fake_http(_self, target, timeout):
            return {
                "url": "https://" + target,
                "status_code": 404,
                "headers": {"server": "test"},
                "body_snippet": "There isn't a GitHub Pages site here.",
                "raw": "HTTP/1.1 404\n\nThere isn't a GitHub Pages site here.",
            }

        def fake_dns(_self, target):
            return {"hostname": target, "addresses": [], "cname": "example.github.io"}

        def fake_tls(_self, target, timeout):
            return {"subject": [], "issuer": [], "raw": "no tls"}

        with tempfile.TemporaryDirectory() as temp:
            with patch.object(SkillRunner, "_http_evidence", fake_http):
                with patch.object(SkillRunner, "_dns_evidence", fake_dns):
                    with patch.object(SkillRunner, "_tls_evidence", fake_tls):
                        result = asyncio.run(
                            SkillRunner().run(
                                skill,
                                SkillRunOptions(
                                    target="sub.example.com",
                                    scope=["example.com"],
                                    authorization_confirmed=True,
                                    scope_confirmed=True,
                                    output_root=temp,
                                ),
                            )
                        )
            evidence = json.loads(Path(result["evidence_path"]).read_text(encoding="utf-8"))
        record = evidence["evidence"][0]
        self.assertEqual(record["final_status"], "Likely Vulnerable")
        self.assertFalse(record["proof_performed"])
        self.assertFalse(record["proof_of_control_allowed"])


if __name__ == "__main__":
    unittest.main()
