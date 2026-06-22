import asyncio
import tempfile
import unittest
from pathlib import Path

from agent_registry import get_agent, list_agents
from external_tools import run_tool, tool_status
from technique_memory import TechniqueMemory


class AgentRegistryTests(unittest.TestCase):
    def test_nine_specialist_agents_are_registered(self):
        agents = list_agents()
        self.assertEqual(len(agents), 9)
        self.assertIsNotNone(get_agent("validator"))
        self.assertEqual(len({item["name"] for item in agents}), 9)


class ExternalToolTests(unittest.TestCase):
    def test_status_is_structured(self):
        tools = tool_status()
        self.assertGreaterEqual(len(tools), 15)
        self.assertTrue(all("available" in item for item in tools))

    def test_unknown_tool_is_never_executed(self):
        result = asyncio.run(run_tool("not-a-real-tool", ["--dangerous"]))
        self.assertTrue(result.skipped)
        self.assertEqual(result.command, [])

    def test_active_tool_requires_authorization_before_install_check(self):
        result = asyncio.run(run_tool("ffuf", ["-u", "https://example.test/FUZZ"]))
        self.assertTrue(result.skipped)


class TechniqueMemoryTests(unittest.TestCase):
    def test_persists_and_recommends_successful_techniques(self):
        with tempfile.TemporaryDirectory() as directory:
            memory = TechniqueMemory(Path(directory) / "memory.db")
            memory.record(
                "graphql-auth", "confirmed", vuln_class="idor",
                tech_stack=["GraphQL"], findings_count=2, confidence=90,
            )
            self.assertEqual(memory.stats()["runs"], 1)
            recommendations = memory.recommendations(["GraphQL"])
            self.assertEqual(recommendations[0]["technique"], "graphql-auth")


if __name__ == "__main__":
    unittest.main()
