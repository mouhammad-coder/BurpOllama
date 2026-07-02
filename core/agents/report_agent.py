"""Deprecated compatibility shim for older final-findings imports."""

from __future__ import annotations

from core.agents.final_findings_presenter_agent import FinalFindingsPresenterAgent


class ReportAgent(FinalFindingsPresenterAgent):
    """Compatibility alias for older imports.

    New scans use FinalFindingsPresenterAgent directly.
    """

    name = "final-findings-presenter"
    phase = "final_findings"
