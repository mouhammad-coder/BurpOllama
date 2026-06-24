"""Optional external tool integrations.

These wrappers are intentionally best-effort. Missing tools return empty
results with warnings and never block the core scanner.
"""

from core.integrations.tool_checker import check_tool

__all__ = ["check_tool"]
