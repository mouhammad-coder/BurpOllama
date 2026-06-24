from __future__ import annotations

import asyncio
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.auth_agent import AuthAgent, decode_jwt


def _jwt(header: dict, payload: dict) -> str:
    def encode(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return "{}.{}.signature".format(encode(header), encode(payload))


class _Scheduler:
    def __init__(self):
        self.states = {}

    def state(self, name):
        self.states.setdefault(
            name,
            SimpleNamespace(findings=0, last_event="", status="pending"),
        )
        return self.states[name]


class _RateLimiter:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1
        return 0


class _Scope:
    allowed_domains = ["example.com"]

    def allows(self, url):
        return "example.com" in str(url)

    def to_dict(self):
        return {"target": "https://example.com", "allowed_domains": ["example.com"]}


class _Context:
    def __init__(self, recon, output):
        self.scan = {
            "id": "auth-observation-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(mode="passive")
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))

    async def log(self, message, level="info", **kwargs):
        self.events.append(("log", {"message": message, "level": level, **kwargs}))


class AuthObservationTests(unittest.TestCase):
    def test_jwt_decoder_handles_malformed_token_without_crash(self):
        self.assertIsNone(decode_jwt("not.a.jwt"))
        self.assertIsNone(decode_jwt("abc.def"))

    def test_alg_none_detected_correctly_in_fixture_token(self):
        token = _jwt(
            {"alg": "none", "typ": "JWT"},
            {"sub": "123", "email": "person@example.com", "role": "admin"},
        )
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {"Authorization": "Bearer {}".format(token)},
                    "body": "",
                }]
            }, temp)
            findings = asyncio.run(AuthAgent().run(ctx))
        alg_findings = [
            finding for finding in findings
            if finding.get("vuln_type") == "JWT Algorithm None Observation"
        ]
        self.assertTrue(alg_findings)
        self.assertEqual(alg_findings[0]["exploitability_status"], "candidate")
        artifact = alg_findings[0]["evidence_artifact"]
        self.assertTrue(Path(artifact["artifact_path"]).exists())
        self.assertEqual(artifact["metadata"]["decoded_header"]["alg"], "none")

    def test_missing_httponly_flagged_from_fixture_header(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {},
                    "set_cookie_headers": ["session=abc123; Path=/; Secure; SameSite=Lax"],
                    "body": "",
                }]
            }, temp)
            findings = asyncio.run(AuthAgent().run(ctx))
        self.assertTrue(any(
            finding.get("vuln_type") == "Session Cookie Missing Flags"
            and "HttpOnly" in finding.get("evidence", "")
            for finding in findings
        ))

    def test_oauth_redirect_uri_to_http_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context({
                "urls": [
                    "https://example.com/oauth/authorize?client_id=abc&redirect_uri=http%3A%2F%2Fexample.com%2Fcallback"
                ]
            }, temp)
            findings = asyncio.run(AuthAgent().run(ctx))
        self.assertTrue(any(
            finding.get("vuln_type") == "OAuth Redirect URI Observation"
            and finding.get("exploitability_status") == "candidate"
            for finding in findings
        ))

    def test_no_finding_marked_confirmed_without_artifact(self):
        token = _jwt({"alg": "none"}, {"sub": "123"})
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context({
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {"Authorization": "Bearer {}".format(token)},
                    "body": "",
                }]
            }, temp)
            with patch(
                "core.agents.auth_agent.write_evidence_artifact",
                return_value={"artifact_path": "", "raw_request": ""},
            ):
                findings = asyncio.run(AuthAgent().run(ctx))
        self.assertTrue(findings)
        self.assertFalse(any(
            finding.get("exploitability_status") == "confirmed"
            for finding in findings
        ))

    def test_passive_mode_sends_no_auth_probe_requests(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = _Context({
                "urls": ["https://example.com/login"],
                "http_observations": [{
                    "url": "https://example.com/login",
                    "headers": {"Set-Cookie": "sid=abc123; Path=/"},
                    "body": "",
                }],
            }, temp)
            findings = asyncio.run(AuthAgent().run(ctx))
        self.assertTrue(findings)
        self.assertEqual(ctx.tested_urls, set())
        self.assertEqual(ctx.rate_limiter.calls, 0)


if __name__ == "__main__":
    unittest.main()
