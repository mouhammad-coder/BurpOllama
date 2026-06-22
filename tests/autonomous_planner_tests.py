import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autonomous_planner import PlannerState, WorkingMemory
from autopilot_state import AutopilotStateStore


def run_tests():
    memory = WorkingMemory(step_budget=10, time_budget=60)
    priority = memory.get_next_priority(
        ["https://example.test/api/users?id=1", "https://example.test/login"],
        [],
    )
    assert priority in {"SQL Injection", "Auth Bypass", "IDOR"}
    ranked = memory.prioritize_classes([
        ("Security Headers", object()),
        ("SQL Injection", object()),
        ("CORS", object()),
    ], ["https://example.test/search?q=x"])
    assert ranked[0][0] == "SQL Injection"

    memory.record_step("SQL Injection", "completed", 2)
    assert memory.observations
    assert memory.should_continue()
    memory.record_step("Repeated", "completed", 0)
    memory.record_step("Repeated", "completed", 0)
    memory.record_step("Repeated", "completed", 0)
    assert memory.is_loop_detected()
    assert not memory.should_continue()
    assert memory.state == PlannerState.BUDGET_EXCEEDED
    assert "finding(s)" in memory.summarize_progress()

    restored = WorkingMemory.from_dict(memory.to_dict())
    assert restored.completed_steps == memory.completed_steps
    assert restored.loop_detection == memory.loop_detection
    assert restored.state == PlannerState.BUDGET_EXCEEDED

    resumable = WorkingMemory(step_budget=20, time_budget=120)
    resumable.record_step("Recon", "completed", 1)
    resumable_copy = WorkingMemory.from_dict(resumable.to_dict())
    assert resumable_copy.should_continue()
    assert resumable_copy.completed_steps[0]["step"] == "Recon"

    with tempfile.TemporaryDirectory() as directory:
        store = AutopilotStateStore(str(Path(directory) / "autopilot.db"))
        store.create_run("scan-1", "https://example.test")
        store.update_run(
            "scan-1",
            checkpoint={"planner": resumable.to_dict()},
        )
        durable = store.get_run("scan-1")
        durable_copy = WorkingMemory.from_dict(
            durable["checkpoint"]["planner"]
        )
        assert durable_copy.completed_steps[0]["step"] == "Recon"
        assert durable_copy.step_budget == 20

        def add_event(index):
            store.event("scan-1", "concurrent.test", {"index": index})

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(add_event, range(32)))
        events = store.recent_events("scan-1", limit=100)
        concurrent = [
            event for event in events
            if event["event_type"] == "concurrent.test"
        ]
        assert len(concurrent) == 32

    print("AUTONOMOUS PLANNER TESTS: PASS")


if __name__ == "__main__":
    run_tests()
