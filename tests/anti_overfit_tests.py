from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agents.hunt_agents import HuntCoordinatorAgent
from zero_fp_gate import apply_zero_fp_gate


class _FakeScheduler:
    def __init__(self):
        self.runs = []
        self.states = {}

    def state(self, name):
        self.states.setdefault(
            name,
            SimpleNamespace(status="pending", findings=0, last_event=""),
        )
        return self.states[name]

    async def run(self, name, callback):
        self.runs.append(name)
        return await callback()

    async def gather_safe(self, items):
        self.runs.extend(name for name, _callback in items)
        return []

    async def checkpoint(self):
        return None


class _FakeScope:
    allowed_domains = ["example.test"]

    def allows(self, _url):
        return True

    def to_dict(self):
        return {"allowed_domains": self.allowed_domains}


class _FakeRateLimiter:
    async def acquire(self):
        return 0


class _FakeContext:
    def __init__(self, mode="bounty"):
        self.scan = {
            "id": "test-scan",
            "adaptive_plan": {
                "enabled_modules": ["Security Headers"],
                "level": "LIGHT",
                "max_urls": 1,
            },
        }
        self.options = SimpleNamespace(
            mode=mode,
            internal_mode="passive_only" if mode == "passive" else "conservative",
            rate_limit=2.0,
            concurrency=1,
            timeout=1.0,
            time_budget=30,
        )
        self.scheduler = _FakeScheduler()
        self.scope = _FakeScope()
        self.rate_limiter = _FakeRateLimiter()
        self.recon = {
            "urls": ["https://example.test/"],
            "live_hosts": [{"url": "https://example.test/"}],
        }
        self.raw_findings = []
        self.tested_urls = set()
        self.events = []

    async def emit(self, event_type, **data):
        self.events.append((event_type, data))

    async def log(self, message, level="info", **_kwargs):
        self.events.append(("log", {"message": message, "level": level}))


class AntiOverfitBehaviorTests(unittest.TestCase):
    def test_active_normal_hunt_does_not_invoke_benchmark_or_lab_validator(self):
        ctx = _FakeContext(mode="bounty")

        async def fake_run_hunt(*_args, **_kwargs):
            return []

        with patch("core.agents.hunt_agents.run_hunt", fake_run_hunt):
            asyncio.run(HuntCoordinatorAgent().run(ctx))

        joined = " ".join(ctx.scheduler.runs)
        self.assertNotIn("lab", joined.lower())
        self.assertNotIn("benchmark", joined.lower())
        self.assertNotIn("juice", joined.lower())
        self.assertNotIn("lab_validation", ctx.scan)
        self.assertNotIn("benchmark", ctx.scan)

    def test_passive_mode_never_enters_active_hunt_engine(self):
        ctx = _FakeContext(mode="passive")

        async def fake_passive(_self, context):
            context.raw_findings.append({"title": "passive observation"})
            return context.raw_findings

        async def forbidden_run_hunt(*_args, **_kwargs):
            raise AssertionError("passive mode must not call active run_hunt")

        with patch.object(HuntCoordinatorAgent, "_passive_observations", fake_passive):
            with patch("core.agents.hunt_agents.run_hunt", forbidden_run_hunt):
                findings = asyncio.run(HuntCoordinatorAgent().run(ctx))

        self.assertEqual(len(findings), 1)

    def test_confirmed_without_evidence_artifact_is_demoted(self):
        with tempfile.TemporaryDirectory() as temp:
            finding = {
                "title": "SQL Injection",
                "vuln_type": "SQL Injection",
                "severity": "HIGH",
                "confidence": 95,
                "url": "https://example.test/search?q='",
                "evidence": "HTTP 200 with sql error",
                "business_impact": "Could expose database contents.",
                "reproduction_steps": ["GET baseline", "GET payload", "Compare responses"],
                "remediation": "Use parameterized queries.",
                "exploitability_status": "confirmed",
                "evidence_strength": "strong",
                "false_positive_risk": "low",
                "redaction_status": "redacted",
            }
            result = apply_zero_fp_gate(
                [finding],
                {"allowed_domains": ["example.test"]},
                scan_context={"tmp": temp},
            )
        self.assertEqual(result["valid_bugs"], [])
        self.assertEqual(result["candidates"], [])
        self.assertTrue(result["needs_more_proof"])
        self.assertIn(
            "missing_evidence_artifact",
            result["needs_more_proof"][0].get("zero_fp_failed_checks", []),
        )

    def test_probable_without_evidence_artifact_is_not_report_ready(self):
        finding = {
            "title": "CORS credentialed origin reflection",
            "vuln_type": "CORS Misconfiguration",
            "severity": "MEDIUM",
            "confidence": 82,
            "url": "https://example.test/api/account",
            "evidence": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true",
            "business_impact": "A malicious allowed origin could read authenticated API responses.",
            "reproduction_steps": [
                "Send request with Origin header.",
                "Observe reflected Access-Control-Allow-Origin.",
                "Observe Access-Control-Allow-Credentials: true.",
            ],
            "remediation": "Use a strict CORS allowlist and avoid credentialed wildcard/reflected origins.",
            "exploitability_status": "probable",
            "evidence_strength": "moderate",
            "false_positive_risk": "medium",
            "redaction_status": "redacted",
        }
        result = apply_zero_fp_gate(
            [finding],
            {"allowed_domains": ["example.test"]},
        )
        self.assertEqual(result["valid_bugs"], [])
        self.assertEqual(result["candidates"], [])
        self.assertTrue(result["needs_more_proof"])
        self.assertIn(
            "missing_evidence_artifact",
            result["needs_more_proof"][0].get("zero_fp_failed_checks", []),
        )

    def test_medium_candidate_without_evidence_artifact_needs_more_proof(self):
        finding = {
            "title": "Upload endpoint candidate",
            "vuln_type": "File Upload Endpoint Candidate",
            "severity": "MEDIUM",
            "confidence": 60,
            "url": "https://example.test/upload",
            "evidence": "multipart form observed",
            "business_impact": "Upload parsing and storage behavior requires manual validation.",
            "reproduction_steps": ["Visit upload form", "Inspect enctype"],
            "remediation": "Validate uploaded content and store files safely.",
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "medium",
            "redaction_status": "redacted",
        }
        result = apply_zero_fp_gate(
            [finding],
            {"allowed_domains": ["example.test"]},
        )
        self.assertEqual(result["valid_bugs"], [])
        self.assertEqual(result["candidates"], [])
        self.assertTrue(result["needs_more_proof"])
        self.assertIn(
            "missing_evidence_artifact",
            result["needs_more_proof"][0].get("zero_fp_failed_checks", []),
        )


class AntiOverfitStaticTests(unittest.TestCase):
    LAB_INDICATORS = (
        "juice-shop",
        "Juice Shop",
        "bkimminich",
        "localhost:3000",
        "127.0.0.1:3000",
        ":3000",
        "/rest/products/search",
        "/administration",
        "/ftp",
        "/api-docs",
    )

    ALLOWED_PARTS = (
        str(Path("core") / "benchmarks"),
        str(Path("tests") / "anti_overfit_tests.py"),
        str(Path("docs")),
        "README",
    )

    def test_lab_indicators_are_not_in_normal_scan_path(self):
        root = Path(__file__).resolve().parents[1]
        violations = []
        for path in root.rglob("*.py"):
            rel = str(path.relative_to(root))
            if any(part in rel for part in self.ALLOWED_PARTS):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for indicator in self.LAB_INDICATORS:
                present = indicator in text
                if indicator == ":3000":
                    import re

                    present = bool(re.search(r"(?<!\[):3000(?!\d)", text))
                if present:
                    if rel == "cli.py" and "benchmark" in text:
                        continue
                    violations.append((rel, indicator))
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
