from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

import main


class ApiBucketTests(unittest.TestCase):
    def test_buckets_fall_back_to_scan_local_findings_and_scope(self):
        scan_id = "api-bucket-local"
        original_scan = main.scans.get(scan_id)
        original_findings = list(main.findings_store)
        try:
            main.findings_store.clear()
            main.scans[scan_id] = {
                "id": scan_id,
                "target": "https://example.test",
                "scope": {
                    "allowed_domains": ["example.test"],
                    "active_testing_enabled": True,
                    "passive_only_mode": False,
                },
                "recon": {"tech_stack": []},
                "triaged_findings": [{
                    "id": "local-info",
                    "scan_id": scan_id,
                    "title": "Informational manual review item",
                    "vuln_type": "Upload Server Path Disclosure",
                    "severity": "INFO",
                    "confidence": 65,
                    "url": "https://example.test/upload",
                    "affected_url": "https://example.test/upload",
                    "evidence": "HTTP/1.1 500 response body includes /var/www/app/uploads",
                    "business_impact": "Server path disclosure supports manual upload validation.",
                    "exploitability_status": "candidate",
                    "evidence_strength": "weak",
                    "false_positive_risk": "medium",
                    "redaction_status": "redacted",
                }],
            }
            with TestClient(main.app) as client:
                response = client.get("/findings/{}/buckets".format(scan_id))
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["scan_id"], scan_id)
            self.assertEqual(payload["summary"]["needs_more_proof"], 1)
            self.assertEqual(payload["needs_more_proof"][0]["title"], "Informational manual review item")
            self.assertEqual(payload["skipped_out_of_scope"], [])
        finally:
            main.findings_store.clear()
            main.findings_store.extend(original_findings)
            if original_scan is None:
                main.scans.pop(scan_id, None)
            else:
                main.scans[scan_id] = original_scan


if __name__ == "__main__":
    unittest.main()
