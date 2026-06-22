import tempfile
import unittest
from pathlib import Path

from discovery_workflows import aggregate_scope_documents
from ai_provider import AIRouter
from config_manager import SETTING_DEFAULTS
from external_tools import TOOL_REGISTRY
from waf_bypass import _path_variants
from web3_scanner import audit_solidity_path, scan_solidity_source


class ScopeAggregationTests(unittest.TestCase):
    def test_disallowed_assets_override_allowed_assets(self):
        result = aggregate_scope_documents([
            ("scope.json", '{"allowed_assets":["*.example.com","admin.example.com"],"disallowed_assets":["admin.example.com"]}')
        ])
        self.assertEqual(result["allowed_assets"], ["*.example.com"])
        self.assertFalse(result["confirmed"])


class ToolExpansionTests(unittest.TestCase):
    def test_network_tls_cms_and_kubernetes_tools_are_registered(self):
        self.assertTrue({
            "naabu",
            "nmap",
            "testssl.sh",
            "droopescan",
            "kube-hunter",
            "trivy",
            "crlfuzz",
        } <= set(TOOL_REGISTRY))


class WafWorkflowTests(unittest.TestCase):
    def test_variants_remain_on_same_origin(self):
        variants = _path_variants("https://example.test/api?q=1")
        self.assertTrue(all(item.startswith("https://example.test/") for item in variants))


class Web3Tests(unittest.TestCase):
    def test_detects_high_risk_solidity_patterns(self):
        findings = scan_solidity_source(
            "contract X { function x(address a) external { require(tx.origin == a); selfdestruct(payable(a)); } }"
        )
        self.assertEqual({item["rule_id"] for item in findings}, {"TX_ORIGIN_AUTH", "UNRESTRICTED_SELFDESTRUCT"})

    def test_audits_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Token.sol"
            path.write_text("contract T { function x(address a) external { a.delegatecall(\"\"); } }", encoding="utf-8")
            result = audit_solidity_path(directory)
            self.assertEqual(result["files_scanned"], 1)
            self.assertTrue(result["findings"])


class ProviderExpansionTests(unittest.TestCase):
    def test_extended_provider_registry_and_settings_match(self):
        names = {provider.name for provider in AIRouter().providers}
        self.assertTrue({"groq", "mistral", "deepseek", "together", "custom"} <= names)
        self.assertTrue({
            "GROQ_API_KEY", "MISTRAL_API_KEY", "DEEPSEEK_API_KEY",
            "TOGETHER_API_KEY", "CUSTOM_AI_API_KEY",
        } <= set(SETTING_DEFAULTS))


if __name__ == "__main__":
    unittest.main()
