import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waf_engine import ThrottleManager
from waf_response_intelligence import (
    ResponseBaseline,
    ResponseFingerprint,
    classify_response,
)


def run_tests():
    normal_body = (
        '<html><form><input name="csrf_token"></form>'
        '{"user_id":"123","profile":"test"}</html>'
    )
    block_body = (
        "<html><title>Attention Required! | Cloudflare</title>"
        "Sorry, you have been blocked. Cloudflare Ray ID: abcdef1234567890"
        "</html>"
    )
    normal = ResponseFingerprint.build(
        403, normal_body, {"Content-Type": "text/html"}
    )
    blocked = ResponseFingerprint.build(
        403, block_body, {"CF-Ray": "abcdef1234567890-LHR"}
    )
    baseline = ResponseBaseline(normal=normal, blocked=blocked)

    app_forbidden = classify_response(normal, baseline)
    assert app_forbidden["classification"] == "application_response"
    assert not app_forbidden["is_block"]

    waf_block = classify_response(blocked, baseline)
    assert waf_block["classification"] == "waf_block"
    assert waf_block["is_block"]
    assert waf_block["vendor"] == "Cloudflare"
    assert waf_block["log_id"]

    challenge = classify_response(
        ResponseFingerprint.build(
            200,
            "<html>Checking your browser<form id='challenge-form'></form></html>",
            {},
        )
    )
    assert challenge["classification"] == "challenge"
    assert challenge["is_block"]

    limiter = classify_response(ResponseFingerprint.build(429, "slow down", {}))
    assert limiter["classification"] == "rate_limit"

    manager = ThrottleManager()
    manager.calibrate_responses(
        "https://example.test",
        normal_status=403,
        normal_body=normal_body,
        normal_headers={"Content-Type": "text/html"},
        block_status=403,
        block_body=block_body,
        block_headers={"CF-Ray": "abcdef1234567890-LHR"},
    )
    assert not manager.is_block_response(
        403,
        normal_body,
        {"Content-Type": "text/html"},
        "https://example.test/private",
    )
    assert manager.is_block_response(
        403,
        block_body,
        {"CF-Ray": "abcdef1234567890-LHR"},
        "https://example.test/private",
    )
    status = manager.status()
    classification = status["hosts"].get("example.test", {}).get(
        "last_response_classification", {}
    )
    assert classification["is_block"]

    print("WAF INTELLIGENCE TESTS: PASS")


if __name__ == "__main__":
    run_tests()
