import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from validation_enhancements import (
    calculate_cvss_40,
    keep_best_similar,
    report_readiness,
)


def finding(identifier, quality=90, evidence="HTTP/1.1 200 OK\n{\"user_id\":2}"):
    return {
        "id": identifier,
        "vuln_type": "IDOR",
        "vulnerability_class": "IDOR",
        "affected_url": "https://example.test/api/users/123",
        "url": "https://example.test/api/users/123",
        "confidence": 95,
        "severity": "HIGH",
        "exploitability_status": "confirmed",
        "quality_score": quality,
        "business_impact": "Another user's controlled profile is exposed.",
        "evidence": evidence,
        "reproduction_steps": ["Login as A", "Request B's object", "Observe B's data"],
    }


def run_tests():
    item = finding("best")
    cvss = calculate_cvss_40(item)
    assert cvss["vector"].startswith("CVSS:4.0/")
    assert 0 <= cvss["score"] <= 10
    item["cvss_40_score"] = cvss["score"]
    readiness = report_readiness(item, True)
    assert readiness["status"] == "READY"

    lower = finding("lower", quality=70)
    lower["affected_url"] = "https://example.test/api/users/456"
    lower["url"] = lower["affected_url"]
    lower["cvss_40_score"] = cvss["score"]
    kept, discarded = keep_best_similar([lower, item])
    assert kept[0]["id"] == "best"
    assert discarded[0]["duplicate_of"] == "best"
    assert "DUPLICATE" in discarded[0]["rejection_reason_codes"]

    not_ready = finding("candidate", quality=50, evidence="possible issue")
    not_ready["exploitability_status"] = "candidate"
    assert report_readiness(not_ready, True)["status"] == "NOT_READY"

    print("VALIDATION ENHANCEMENTS TESTS: PASS")


if __name__ == "__main__":
    run_tests()
