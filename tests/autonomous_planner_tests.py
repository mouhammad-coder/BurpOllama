import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autonomous_planner import PlannerState, WorkingMemory


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

    print("AUTONOMOUS PLANNER TESTS: PASS")


if __name__ == "__main__":
    run_tests()
