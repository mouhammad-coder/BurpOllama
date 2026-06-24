from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.ai_triage_agent import (
    AITriageAgent,
    build_ollama_triage_prompt,
)
from core.config import ollama_health
from core.evidence import write_evidence_artifact


class _Scheduler:
    def __init__(self):
        self.states = {}

    def state(self, name):
        self.states.setdefault(name, SimpleNamespace(findings=0, last_event=""))
        return self.states[name]


class _Context:
    def __init__(self, finding):
        self.scan = {
            "id": "ollama-triage-test",
            "target": "https://example.com",
            "ai": {"agents_enabled": True},
        }
        self.options = SimpleNamespace()
        self.raw_findings = [finding]
        self.triaged_findings = []
        self.scheduler = _Scheduler()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))

    async def log(self, message, level="info", **kwargs):
        self.events.append(("log", {"message": message, "level": level, **kwargs}))


class _Response:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        return None

    def json(self):
        return {"message": {"content": self.content}}


class _FakeAsyncClient:
    response_content = "{}"
    raise_timeout = False
    prompts = []

    def __init__(self, *args, **kwargs):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, json):
        self.__class__.prompts.append(json)
        if self.__class__.raise_timeout:
            raise TimeoutError("timeout")
        return _Response(self.__class__.response_content)


def _finding_with_artifact(temp: str, status: str = "candidate") -> dict:
    scan = {"id": "ollama-triage-test"}
    artifact = write_evidence_artifact(
        scan,
        title="Possible SQL Injection",
        url="https://example.com/search?q=test",
        raw_request=(
            "GET https://example.com/search?q=secret HTTP/1.1\n"
            "Authorization: Bearer very-secret\n"
            "Cookie: sid=very-secret"
        ),
        raw_response="HTTP/1.1 500\n\n" + ("SQL syntax error " * 80),
        matched_indicator="SQL syntax error",
        indicator_location="response body, offset 20",
        agent="injection",
        vuln_class="SQL Injection",
        impact="SQL errors can expose database behavior.",
        fp_check="Indicator absent from baseline response.",
        confirmed=False,
        filename_prefix="ai-test",
    )
    original = Path(artifact["artifact_path"])
    target = Path(temp) / original.name
    target.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
    artifact["artifact_path"] = str(target)
    artifact["path"] = str(target)
    return {
        "id": "finding-1",
        "title": "Possible SQL Injection",
        "vuln_type": "SQL Injection",
        "url": "https://example.com/search?q=test",
        "exploitability_status": status,
        "evidence_artifact": artifact,
    }


class OllamaAITriageTests(unittest.TestCase):
    def test_mock_ollama_valid_json_merges_ai_triage(self):
        with tempfile.TemporaryDirectory() as temp:
            finding = _finding_with_artifact(temp)
            ctx = _Context(finding)
            _FakeAsyncClient.response_content = json.dumps({
                "exploitability": "high",
                "false_positive_risk": "low",
                "recommended_action": "Validate safely with stronger proof.",
                "triage_note": "The SQL error is useful but still needs proof.",
            })
            _FakeAsyncClient.raise_timeout = False
            with patch("core.agents.ai_triage_agent.ollama_health", return_value={
                "running": True,
                "model_available": True,
            }), patch("core.agents.ai_triage_agent.ollama_config", return_value={
                "base_url": "http://localhost:11434",
                "model": "mistral:7b-instruct",
                "timeout": 1,
            }), patch("core.agents.ai_triage_agent.httpx.AsyncClient", _FakeAsyncClient):
                triaged = asyncio.run(AITriageAgent().run(ctx))
        self.assertEqual(triaged[0]["exploitability_status"], "candidate")
        self.assertEqual(triaged[0]["ai_triage"]["exploitability"], "high")
        self.assertEqual(triaged[0]["ai_triage"]["false_positive_risk"], "low")

    def test_malformed_json_leaves_finding_status_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            finding = _finding_with_artifact(temp, status="needs_manual_validation")
            ctx = _Context(finding)
            _FakeAsyncClient.response_content = "not json"
            _FakeAsyncClient.raise_timeout = False
            with patch("core.agents.ai_triage_agent.ollama_health", return_value={
                "running": True,
                "model_available": True,
            }), patch("core.agents.ai_triage_agent.ollama_config", return_value={
                "base_url": "http://localhost:11434",
                "model": "mistral:7b-instruct",
                "timeout": 1,
            }), patch("core.agents.ai_triage_agent.httpx.AsyncClient", _FakeAsyncClient):
                triaged = asyncio.run(AITriageAgent().run(ctx))
        self.assertEqual(triaged[0]["exploitability_status"], "needs_manual_validation")
        self.assertIsNone(triaged[0]["ai_triage"])

    def test_timeout_sets_null_ai_triage_and_logs_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            finding = _finding_with_artifact(temp)
            ctx = _Context(finding)
            _FakeAsyncClient.raise_timeout = True
            with patch("core.agents.ai_triage_agent.ollama_health", return_value={
                "running": True,
                "model_available": True,
            }), patch("core.agents.ai_triage_agent.ollama_config", return_value={
                "base_url": "http://localhost:11434",
                "model": "mistral:7b-instruct",
                "timeout": 1,
            }), patch("core.agents.ai_triage_agent.httpx.AsyncClient", _FakeAsyncClient):
                triaged = asyncio.run(AITriageAgent().run(ctx))
        self.assertIsNone(triaged[0]["ai_triage"])
        self.assertTrue(any(event[0] == "log" and event[1]["level"] == "warning" for event in ctx.events))

    def test_prompt_builder_strips_sensitive_headers_and_truncates_response(self):
        finding = {"url": "https://example.com/search?q=test"}
        artifact = {
            "vuln_class": "SQL Injection",
            "url": "https://example.com/search?q=test",
            "raw_request": (
                "GET https://example.com/search?q=secret&sort=desc HTTP/1.1\n"
                "Authorization: Bearer secret\nCookie: sid=secret"
            ),
            "raw_response": "A" * 900,
            "matched_indicator": "SQL syntax error",
            "indicator_location": "response body, offset 20",
            "impact": "impact",
            "fp_check": "fp",
        }
        prompt = build_ollama_triage_prompt(finding, artifact)
        self.assertNotIn("Bearer secret", prompt)
        self.assertNotIn("sid=secret", prompt)
        self.assertIn("q=<redacted>", prompt)
        self.assertNotIn("q=secret", prompt)
        data = json.loads(prompt)
        self.assertEqual(len(data["finding"]["raw_response_first_512"]), 512)

    def test_ai_output_never_changes_confirmed_status(self):
        with tempfile.TemporaryDirectory() as temp:
            finding = _finding_with_artifact(temp, status="confirmed")
            ctx = _Context(finding)
            with patch("core.agents.ai_triage_agent.ollama_health", return_value={
                "running": True,
                "model_available": True,
            }):
                triaged = asyncio.run(AITriageAgent().run(ctx))
        self.assertEqual(triaged[0]["exploitability_status"], "confirmed")
        self.assertNotIn("ai_triage", triaged[0])

    def test_doctor_ollama_health_handles_not_running(self):
        class FailingClient:
            def __init__(self, *args, **kwargs):
                return None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, url):
                raise TimeoutError("not running")

        with patch("core.config.httpx.AsyncClient", FailingClient):
            health = asyncio.run(ollama_health())
        self.assertFalse(health["running"])
        self.assertIn("ollama pull", health["setup"])


if __name__ == "__main__":
    unittest.main()
