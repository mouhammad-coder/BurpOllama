import asyncio
import json
import sqlite3
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from contextlib import closing

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
import program_intelligence as intelligence


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeClient:
    responses = []
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, *args, **kwargs):
        self.calls.append(url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


async def async_contracts(cache_path: Path):
    original_client = intelligence.httpx.AsyncClient
    original_cache = intelligence.CACHE_PATH
    intelligence.httpx.AsyncClient = FakeClient
    intelligence.CACHE_PATH = cache_path
    try:
        FakeClient.calls = []
        FakeClient.responses = [FakeResponse(payload={
            "name": "Example Program",
            "structured_scopes": [
                {
                    "asset_identifier": "*.example.test",
                    "eligible_for_submission": True,
                }
            ],
            "bounty_table": {"critical": "$10,000"},
        })]
        first = await intelligence.fetch_hackerone_scope("example")
        second = await intelligence.fetch_hackerone_scope("example")
        assert first == second
        assert len(FakeClient.calls) == 1
        assert first["allowed_assets"] == ["*.example.test"]

        with closing(sqlite3.connect(cache_path)) as connection:
            connection.execute(
                "UPDATE intelligence_cache SET created_at=?",
                (time.time() - intelligence.CACHE_TTL_SECONDS - 10,),
            )
            connection.commit()
        FakeClient.responses = [FakeResponse(status_code=503, payload={})]
        expired = await intelligence.fetch_hackerone_scope("example")
        assert expired == {}
        assert len(FakeClient.calls) == 2

        FakeClient.responses = [
            FakeResponse(payload=ValueError("malformed JSON")),
        ]
        malformed = await intelligence.fetch_hackerone_scope("malformed")
        assert malformed == {}

        FakeClient.responses = [TimeoutError("offline")]
        timed_out = await intelligence.lookup_nvd_cve("timeout-product")
        assert timed_out == []

        FakeClient.responses = [FakeResponse(payload={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "published": "2026-01-01T00:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "Critical example issue."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-0002",
                        "published": "2026-01-02T00:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "Low example issue."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "LOW"}}
                            ]
                        },
                    }
                },
            ]
        })]
        cves = await intelligence.lookup_nvd_cve("example-product")
        assert [item["cve_id"] for item in cves] == ["CVE-2026-0001"]

        def write_cache(index):
            key = intelligence._cache_key("concurrency", str(index))
            intelligence._cache_set(key, {"index": index})
            return intelligence._cache_get(key)

        with ThreadPoolExecutor(max_workers=8) as executor:
            cached = list(executor.map(write_cache, range(32)))
        assert [item["index"] for item in cached] == list(range(32))
    finally:
        intelligence.httpx.AsyncClient = original_client
        intelligence.CACHE_PATH = original_cache


def api_contracts():
    original_scope = main.fetch_hackerone_scope
    original_cves = main.lookup_nvd_cve

    async def fake_scope(slug):
        return {
            "allowed_assets": ["*.{}.test".format(slug)],
            "disallowed_assets": [],
            "bounty_table": {"critical": "$20,000"},
            "program_url": "https://hackerone.com/{}".format(slug),
        }

    async def fake_cves(technology):
        return [{
            "cve_id": "CVE-2026-9999",
            "severity": "HIGH",
            "description": "{} test CVE".format(technology),
            "published_date": "2026-01-01",
        }]

    main.fetch_hackerone_scope = fake_scope
    main.lookup_nvd_cve = fake_cves
    planner_scan_id = "contract-planner-scan"
    original_scan = main.scans.get(planner_scan_id)
    main.scans[planner_scan_id] = {
        "id": planner_scan_id,
        "target": "https://example.test",
        "planner": {
            "state": "RUNNING",
            "completed_steps": [{"step": "Recon"}],
        },
        "planner_summary": "Recon complete.",
    }
    try:
        with TestClient(main.app) as client:
            program = client.get("/intelligence/program?slug=example")
            assert program.status_code == 200
            assert program.json()["available"]
            assert program.json()["attractiveness"]["score"] > 0

            cve = client.get("/intelligence/cve?tech=wordpress")
            assert cve.status_code == 200
            assert cve.json()["cves"][0]["cve_id"] == "CVE-2026-9999"

            planner = client.get(
                "/scan/{}/planner".format(planner_scan_id)
            )
            assert planner.status_code == 200
            assert planner.json()["planner"]["state"] == "RUNNING"
            assert planner.json()["summary"] == "Recon complete."
    finally:
        main.fetch_hackerone_scope = original_scope
        main.lookup_nvd_cve = original_cves
        if original_scan is None:
            main.scans.pop(planner_scan_id, None)
        else:
            main.scans[planner_scan_id] = original_scan


def run_tests():
    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(
            async_contracts(Path(directory) / "intelligence.db")
        )
    api_contracts()
    print("PROGRAM INTELLIGENCE CONTRACT TESTS: PASS")


if __name__ == "__main__":
    run_tests()
