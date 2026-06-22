import asyncio
import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporter import (
    generate_csv_report,
    generate_full_report,
    generate_json_report,
    generate_sarif_report,
)
from validation_enhancements import calculate_cvss_40, report_readiness


def fixture():
    finding = {
        "id": "F-REPORT-1",
        "scan_id": "scan-report",
        "title": "Confirmed IDOR",
        "vuln_type": "IDOR",
        "vulnerability_class": "IDOR",
        "affected_url": "https://example.test/api/users/2",
        "url": "https://example.test/api/users/2",
        "method": "GET",
        "severity": "HIGH",
        "confidence": 95,
        "exploitability_status": "confirmed",
        "evidence_strength": "strong",
        "false_positive_risk": "low",
        "business_impact": "A test user can read another test user's profile.",
        "technical_impact": "Object ownership is not checked.",
        "description": "The endpoint returns another controlled user's data.",
        "evidence": (
            "HTTP/1.1 200 OK\nContent-Type: application/json\n"
            '{"user_id":2,"api_key":"[REDACTED]"}'
        ),
        "reproduction_steps": [
            "Authenticate as controlled user A.",
            "Request controlled user B's identifier.",
            "Observe user B's profile in the HTTP 200 response.",
        ],
        "remediation": "Enforce object-level authorization.",
        "redaction_status": "redacted",
        "verdict": "PASS",
        "quality_score": 92,
        "_scope_match": True,
    }
    cvss = calculate_cvss_40(finding)
    finding["cvss_40_score"] = cvss["score"]
    finding["cvss_40_vector"] = cvss["vector"]
    finding["cvss_plus_plus"] = 8.8
    finding["classification"] = "High"
    finding["report_readiness"] = report_readiness(finding, True)
    finding["rejection_reason_codes"] = []
    return finding


async def async_report_test():
    finding = fixture()
    finding["evidence"] = (
        "HTTP/1.1 200 OK\nContent-Type: application/json\n"
        '{"user_id":2,"api_key":"AKIA1234567890ABCDEF"}'
    )
    report = await generate_full_report(
        "https://example.test",
        {"live_hosts": [], "js_findings": [], "stats": {}},
        [finding],
        {"exploit_chains": {}, "coverage": {}},
        api_key="",
        scope={"allowed_domains": ["example.test"]},
    )
    assert "CVSS 4.0" in report
    assert finding["cvss_40_vector"] in report
    assert "Report Readiness" in report
    assert "AKIA1234567890ABCDEF" not in report


def run_tests():
    asyncio.run(async_report_test())
    finding = fixture()
    json_report = generate_json_report(
        "https://example.test",
        {},
        [finding],
        {},
        {"allowed_domains": ["example.test"]},
    )
    serialized = json.dumps(json_report)
    assert "cvss_40_score" in serialized
    assert "report_readiness" in serialized

    csv_report = generate_csv_report([finding])
    rows = list(csv.DictReader(io.StringIO(csv_report)))
    assert rows and rows[0]["id"] == "F-REPORT-1"
    assert rows[0]["cvss_40_vector"].startswith("CVSS:4.0/")
    assert rows[0]["cvss_40_official"] == "True"
    assert rows[0]["ready_to_submit"] == "True"

    sarif = generate_sarif_report("https://example.test", [finding])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"].startswith("https://example.test/")

    print("REPORT SNAPSHOT TESTS: PASS")


if __name__ == "__main__":
    run_tests()
