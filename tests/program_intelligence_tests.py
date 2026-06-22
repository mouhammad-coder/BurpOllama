import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from program_intelligence import (
    _normalize_policy,
    _parse_disclosed_reports,
    score_program_attractiveness,
)


def run_tests():
    policy = _normalize_policy({
        "name": "Example",
        "structured_scopes": [
            {"asset_identifier": "*.example.com", "eligible_for_submission": True},
            {"asset_identifier": "hardware.example", "eligible_for_submission": False},
        ],
        "bounty_table": {"critical": "$25,000"},
        "response_time": "fast",
    }, "example")
    assert policy["allowed_assets"] == ["*.example.com"]
    assert policy["disallowed_assets"] == ["hardware.example"]

    score = score_program_attractiveness(policy)
    assert score["score"] >= 70
    assert score["best_assets"][0] == "*.example.com"

    document = """
      <a href="/reports/12345">SQL Injection in search</a>
      <div>Critical $12,500 Public report summary</div>
      <a href="/reports/67890">Stored XSS in profile</a>
      <div>High $2,000 Second summary</div>
    """
    reports = _parse_disclosed_reports(document)
    assert len(reports) == 2
    assert reports[0]["report_id"] == "12345"
    assert "SQL Injection" in reports[0]["title"]

    print("PROGRAM INTELLIGENCE TESTS: PASS")


if __name__ == "__main__":
    run_tests()
