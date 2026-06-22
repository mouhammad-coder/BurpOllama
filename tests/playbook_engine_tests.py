import unittest

from playbook_engine import build_program_playbook, build_scan_playbook


class PlaybookEngineTests(unittest.TestCase):
    def test_prioritizes_auth_api_and_idor_surface(self):
        recon = {
            "urls": [
                "https://example.com/api/v1/users/123",
                "https://example.com/api/v1/orders/456?user_id=123",
                "https://example.com/login",
                "https://example.com/graphql",
            ],
            "tech_stack": ["GraphQL", "React"],
        }
        coverage = {"coverage_percent": 20, "untested_endpoints": 4}
        playbook = build_scan_playbook(recon, [], coverage, {})

        self.assertGreaterEqual(playbook["summary"]["urls"], 4)
        self.assertTrue(playbook["next_best_actions"])
        titles = [item["playbook"] for item in playbook["next_best_actions"][:4]]
        self.assertIn("Access Control / IDOR", titles)
        self.assertIn("API Authorization", titles)
        self.assertTrue(any(gap["type"] == "auth" for gap in playbook["gaps"]))

    def test_marks_related_findings_as_tested(self):
        recon = {"urls": ["https://example.com/search?q=test"]}
        findings = [{
            "id": "F1",
            "vuln_type": "Reflected XSS",
            "severity": "HIGH",
            "url": "https://example.com/search?q=test",
            "exploitability_status": "probable",
        }]
        playbook = build_scan_playbook(recon, findings, {"coverage_percent": 80}, {})

        xss = next(item for item in playbook["ranked_playbooks"] if item["id"] == "xss-client")
        self.assertEqual(xss["status"], "tested")
        self.assertEqual(xss["matching_findings"][0]["id"], "F1")
        self.assertGreater(playbook["readiness_score"], 30)

    def test_program_playbook_is_advisory_and_counts_scope(self):
        program_scope = {
            "allowed_assets": [
                {"asset_identifier": "https://*.example.com"},
                {"asset_identifier": "https://api.example.com"},
            ],
            "disallowed_assets": ["https://legacy.example.com"],
        }
        playbook = build_program_playbook(program_scope, ["wordpress"])

        self.assertEqual(playbook["program_scope_summary"]["allowed_assets"], 2)
        self.assertIn("advisory", playbook["program_scope_summary"]["scope_warning"].lower())
        self.assertTrue(playbook["ranked_playbooks"])


if __name__ == "__main__":
    unittest.main()
