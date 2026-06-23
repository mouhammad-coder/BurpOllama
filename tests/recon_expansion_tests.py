import asyncio
import json
import sys
import types
import unittest

import httpx

from core.ratelimit import RateLimiter
from core import recon_expansion as recon


class _TimeoutClient:
    async def get(self, *args, **kwargs):
        raise httpx.TimeoutException("timeout")


class _FakeTarget:
    def __init__(self, value):
        self.target = value

    def __str__(self):
        return self.target


class _FakeAnswers(list):
    def __init__(self, values, ttl=300):
        super().__init__([_FakeTarget(value) for value in values])
        self.rrset = types.SimpleNamespace(ttl=ttl)


class ReconExpansionTests(unittest.TestCase):
    def test_crtsh_parser_handles_empty_and_malformed_json(self):
        self.assertEqual(recon.parse_crtsh_json("", "example.com"), [])
        self.assertEqual(recon.parse_crtsh_json("{bad json", "example.com"), [])
        parsed = recon.parse_crtsh_json(
            json.dumps([
                {"name_value": "*.api.example.com\nwww.example.com"},
                {"common_name": "outside.test"},
            ]),
            "example.com",
        )
        self.assertEqual(parsed, ["api.example.com", "www.example.com"])

    def test_wayback_parser_deduplicates_and_filters_out_of_scope(self):
        payload = json.dumps([
            ["original"],
            ["https://www.example.com/login"],
            ["https://www.example.com/login"],
            ["https://api.example.com/v1/users"],
            ["https://evil.test/steal"],
        ])
        parsed = recon.parse_wayback_urls(
            payload,
            "example.com",
            lambda url: "evil.test" not in url,
        )
        self.assertEqual(parsed, [
            "https://www.example.com/login",
            "https://api.example.com/v1/users",
        ])

    def test_js_secret_extractor_finds_planted_pattern_and_ignores_noise(self):
        js = """
        const x=!0,y=!1,z='aaaaaaa';
        window.api_key = "sk_live_1234567890abcdef";
        const bearerToken = "Bearer abcdef1234567890";
        const bucket = "assets.s3.amazonaws.com";
        const host = "api.internal";
        """
        extracted = recon.extract_js_intelligence(js)
        self.assertGreaterEqual(len(extracted["secrets"]), 2)
        self.assertTrue(any("api_key" in item["matched_indicator"] for item in extracted["secrets"]))
        self.assertTrue(extracted["s3_buckets"])
        self.assertTrue(extracted["internal_hosts"])
        self.assertFalse(any(item["value_preview"] == "aaaaaa…" for item in extracted["secrets"]))

    def test_subdomain_cname_check_identifies_dangling_cname_with_mocked_dns(self):
        resolver_module = types.ModuleType("dns.resolver")

        class FakeResolver:
            def resolve(self, query, record_type):
                if record_type == "CNAME" and query == "dangling.example.com":
                    return _FakeAnswers(["missing-resource.github.io."], ttl=123)
                raise Exception("no answer")

        resolver_module.Resolver = FakeResolver
        dns_module = types.ModuleType("dns")
        dns_module.resolver = resolver_module
        old_dns = sys.modules.get("dns")
        old_resolver = sys.modules.get("dns.resolver")
        sys.modules["dns"] = dns_module
        sys.modules["dns.resolver"] = resolver_module
        try:
            findings = asyncio.run(
                recon.check_dns_misconfigurations(
                    "example.com",
                    ["dangling.example.com"],
                )
            )
        finally:
            if old_dns is not None:
                sys.modules["dns"] = old_dns
            else:
                sys.modules.pop("dns", None)
            if old_resolver is not None:
                sys.modules["dns.resolver"] = old_resolver
            else:
                sys.modules.pop("dns.resolver", None)
        self.assertTrue(any(item.kind == "dangling_cname_candidate" for item in findings))
        dangling = next(item for item in findings if item.kind == "dangling_cname_candidate")
        self.assertEqual(dangling.ttl, 123)
        self.assertIn("github.io", dangling.evidence)

    def test_recon_sources_skip_gracefully_on_timeout(self):
        async def run():
            limiter = RateLimiter(requests_per_second=50, max_requests=10)
            subdomains = await recon.fetch_passive_subdomains(
                "example.com",
                _TimeoutClient(),
                limiter,
            )
            wayback = await recon.fetch_wayback_urls(
                "example.com",
                _TimeoutClient(),
                limiter,
                lambda url: True,
            )
            return subdomains, wayback

        subdomains, wayback = asyncio.run(run())
        self.assertEqual(subdomains["subdomains"], [])
        self.assertIn("crtsh", subdomains["errors"])
        self.assertEqual(wayback["urls"], [])
        self.assertIn("wayback", wayback["errors"])

    def test_ip_targets_skip_passive_subdomain_sources(self):
        async def run():
            limiter = RateLimiter(requests_per_second=50, max_requests=10)
            return await recon.fetch_passive_subdomains("127.0.0.1", _TimeoutClient(), limiter)

        result = asyncio.run(run())
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["errors"], {})


if __name__ == "__main__":
    unittest.main()
