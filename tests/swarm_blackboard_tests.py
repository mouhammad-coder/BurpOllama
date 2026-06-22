import tempfile
import time
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope_drift_guard import scope_drift, scope_snapshot
from swarm_blackboard import SwarmBlackboard, TriggerPredicate


class SwarmBlackboardTests(unittest.TestCase):
    def test_pheromone_decay_and_trigger_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            board = SwarmBlackboard(Path(directory) / "swarm.db")
            created = time.time()
            board.write(
                "scan-1",
                "recon-agent",
                "HTTP_ENDPOINT",
                "https://example.test",
                {"status": 200},
                pheromone_base=1.0,
                half_life_sec=100,
                created_epoch=created,
            )
            items = board.query(
                "scan-1",
                TriggerPredicate(
                    finding_types=("HTTP_ENDPOINT",),
                    minimum_pheromone=0.49,
                ),
                now_epoch=created + 100,
            )
            self.assertEqual(len(items), 1)
            self.assertAlmostEqual(items[0]["pheromone"], 0.5, places=4)

            triggered = board.triggered(
                "scan-1",
                "classifier",
                TriggerPredicate(
                    finding_types=("HTTP_ENDPOINT",),
                    minimum_pheromone=0.1,
                ),
            )
            self.assertEqual(len(triggered), 1)
            board.commit_cursor(
                "scan-1",
                "classifier",
                triggered[0]["created_epoch"] + 0.001,
            )
            self.assertEqual(
                board.triggered(
                    "scan-1",
                    "classifier",
                    TriggerPredicate(finding_types=("HTTP_ENDPOINT",)),
                ),
                [],
            )

    def test_status_groups_items_by_agent_and_type(self):
        with tempfile.TemporaryDirectory() as directory:
            board = SwarmBlackboard(Path(directory) / "swarm.db")
            board.write("scan-2", "recon-agent", "TECHNOLOGY", "target", {})
            board.write("scan-2", "hunt-agent", "RAW_FINDING", "target", {})
            status = board.status("scan-2")
            self.assertEqual(status["total_items"], 2)
            self.assertEqual(status["items_by_type"]["RAW_FINDING"], 1)
            self.assertEqual(status["items_by_agent"]["recon-agent"], 1)
            ready = board.ready_agents("scan-2")
            self.assertTrue(
                {"classifier", "validator"}
                <= {item["agent_name"] for item in ready}
            )


class ScopeDriftGuardTests(unittest.TestCase):
    def test_reports_changed_authorization_fields(self):
        before = scope_snapshot({
            "allowed_domains": ["example.test"],
            "active_testing_enabled": True,
        })
        result = scope_drift(before, {
            "allowed_domains": ["api.example.test"],
            "active_testing_enabled": False,
        })
        self.assertTrue(result["changed"])
        self.assertIn("allowed_domains", result["changes"])
        self.assertIn("active_testing_enabled", result["changes"])


if __name__ == "__main__":
    unittest.main()
