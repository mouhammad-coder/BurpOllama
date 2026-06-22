import unittest

from auth_coverage_engine import analyze_auth_coverage, classify_auth_endpoint


class AuthCoverageEngineTests(unittest.TestCase):
    def test_classifies_idor_and_api_targets(self):
        result = classify_auth_endpoint("https://example.com/api/v1/users/123?account_id=456")

        self.assertTrue(result["auth_sensitive"])
        self.assertGreaterEqual(result["score"], 70)
        self.assertIn("identifier", " ".join(result["reasons"]).lower())

    def test_warns_when_sensitive_surface_has_no_dual_sessions(self):
        report = analyze_auth_coverage(
            {"urls": ["https://example.com/account/123", "https://example.com/login"]},
            {
                "configured": False,
                "session_a": {"configured": False},
                "session_b": {"configured": False},
            },
            [],
            {"coverage_percent": 10, "skipped_due_to_missing_auth": 2},
        )

        self.assertEqual(report["status"], "not_ready")
        self.assertFalse(report["sessions"]["dual_session_ready"])
        self.assertGreater(report["authorization_surface"]["sensitive_endpoint_templates"], 0)
        self.assertTrue(any("Dual-session" in warning for warning in report["warnings"]))
        self.assertTrue(any("two different user sessions" in step for step in report["next_steps"]))

    def test_dual_sessions_raise_readiness_and_track_findings(self):
        report = analyze_auth_coverage(
            {
                "urls": [
                    "https://example.com/api/orders/1001",
                    "https://example.com/graphql",
                ]
            },
            {
                "tested": 2,
                "violations": 1,
                "mutations_allowed": False,
                "session_a": {
                    "configured": True,
                    "expired": False,
                    "role": "user-a",
                    "session_id": "SES-a",
                },
                "session_b": {
                    "configured": True,
                    "expired": False,
                    "role": "user-b",
                    "session_id": "SES-b",
                },
            },
            [{
                "id": "F1",
                "vuln_type": "BOLA — Session A received Session B data",
                "severity": "HIGH",
                "url": "https://example.com/api/orders/1001",
            }],
            {"coverage_percent": 80},
        )

        self.assertIn(report["status"], {"partial", "ready"})
        self.assertTrue(report["sessions"]["dual_session_ready"])
        self.assertEqual(report["authorization_surface"]["violations"], 1)
        self.assertEqual(report["authorization_surface"]["related_findings"][0]["id"], "F1")

    def test_expired_session_is_not_ready(self):
        report = analyze_auth_coverage(
            {"urls": ["https://example.com/admin/users"]},
            {
                "session_a": {"configured": True, "expired": True},
                "session_b": {"configured": True, "expired": False},
            },
            [],
            {},
        )

        self.assertFalse(report["sessions"]["dual_session_ready"])
        self.assertTrue(any("expired" in warning.lower() for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
