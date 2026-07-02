from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.graphql_agent import GraphQLAgent, INTROSPECTION_BODY


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
    def allows(self, url):
        return "example.com" in str(url)


class _Context:
    def __init__(self, recon, output, mode="passive", program_profile=None):
        self.scan = {
            "id": "graphql-observation-test",
            "target": "https://example.com",
            "options": {"output": output},
        }
        self.options = SimpleNamespace(
            mode=mode,
            timeout=1.0,
            program_profile=program_profile or {},
        )
        self.recon = recon
        self.raw_findings = []
        self.tested_urls = set()
        self.scheduler = _Scheduler()
        self.rate_limiter = _RateLimiter()
        self.scope = _Scope()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))


class _Response:
    status_code = 200
    text = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'


class _Client:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        self.calls.append((url, json))
        return _Response()


class GraphQLObservationTests(unittest.TestCase):
    def _run(self, recon, mode="passive", program_profile=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        ctx = _Context(recon, temp.name, mode=mode, program_profile=program_profile)
        findings = asyncio.run(GraphQLAgent().run(ctx))
        return ctx, findings

    def test_url_pattern_detected_correctly(self):
        for path in (
            "/graphql", "/graphiql", "/graphql/console", "/api/graphql",
            "/gql", "/query", "/v1/graphql",
        ):
            _ctx, findings = self._run({"urls": ["https://example.com{}".format(path)]})
            candidates = [
                finding for finding in findings
                if finding.get("vuln_type") == "GraphQL Endpoint Candidate"
            ]
            self.assertTrue(candidates, path)
            self.assertEqual(candidates[0]["exploitability_status"], "candidate")
            self.assertTrue(Path(candidates[0]["evidence_artifact"]["artifact_path"]).exists())

    def test_introspection_confirmed_with_artifact(self):
        _Client.calls = []
        with patch("core.agents.graphql_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run(
                {"urls": ["https://example.com/graphql"]},
                mode="bounty",
                program_profile={"graphql_introspection_allowed": True},
            )
        self.assertEqual(_Client.calls, [("https://example.com/graphql", INTROSPECTION_BODY)])
        self.assertEqual(ctx.rate_limiter.calls, 1)
        confirmed = [
            finding for finding in findings
            if finding.get("vuln_type") == "GraphQL Introspection Enabled"
        ]
        self.assertTrue(confirmed)
        self.assertEqual(confirmed[0]["exploitability_status"], "confirmed")
        artifact = confirmed[0]["evidence_artifact"]
        self.assertTrue(Path(artifact["artifact_path"]).exists())
        self.assertEqual(artifact["metadata"]["endpoint_url"], "https://example.com/graphql")
        self.assertIn("__schema", artifact["metadata"]["response_first_1kb"])

    def test_no_introspection_without_program_permission(self):
        _Client.calls = []
        with patch("core.agents.graphql_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run(
                {"urls": ["https://example.com/graphql"]},
                mode="bounty",
                program_profile={"graphql_introspection_allowed": False},
            )
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, [])
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertTrue(any(
            data.get("reason") == "graphql_introspection_not_allowed"
            for _event, data in ctx.events
        ))

    def test_no_introspection_in_passive_mode(self):
        _Client.calls = []
        with patch("core.agents.graphql_agent.httpx.AsyncClient", _Client):
            ctx, findings = self._run({"urls": ["https://example.com/graphql"]})
        self.assertTrue(findings)
        self.assertEqual(_Client.calls, [])
        self.assertEqual(ctx.rate_limiter.calls, 0)
        self.assertEqual(ctx.tested_urls, set())

    def test_error_structure_info_finding(self):
        _ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/graphql",
                "status_code": 200,
                "body": (
                    '{"errors":[{"message":"Cannot query field",'
                    '"locations":[{"line":1,"column":2}],"path":["user"]}]}'
                ),
            }]
        })
        errors = [
            finding for finding in findings
            if finding.get("vuln_type") == "GraphQL Error Observation"
        ]
        self.assertTrue(errors)
        self.assertEqual(errors[0]["severity"], "INFO")
        self.assertEqual(errors[0]["exploitability_status"], "candidate")

    def test_non_graphql_json_not_flagged(self):
        _ctx, findings = self._run({
            "http_observations": [{
                "url": "https://example.com/api/users",
                "status_code": 200,
                "body": '{"items":[{"id":1}],"ok":true}',
            }]
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
