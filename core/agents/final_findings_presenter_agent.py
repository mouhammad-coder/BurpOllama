"""Final findings presenter agent.

This replaces report writing. It collects proof-gated findings, separates
Great Findings from Needs Manual Check, redacts sensitive values, and writes
only internal scan artifacts under scans/<scan-id>/.
"""

from __future__ import annotations

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType
from core.findings import final_findings, render_final_tables, write_scan_artifacts


class FinalFindingsPresenterAgent(BaseAgent):
    name = "final-findings-presenter"
    phase = "final_findings"

    async def run(self, context: ScanContext):
        findings = final_findings(context.scan)
        context.scan["final_findings"] = findings
        paths = write_scan_artifacts(context.scan, context.options.output)
        context.artifact_paths = paths
        context.scan["artifact_paths"] = paths
        context.scan["final_output"] = render_final_tables(context.scan, findings)
        await context.emit(
            EventType.FINDINGS_PREPARED,
            agent=self.name,
            phase=self.phase,
            message="Final findings prepared",
            format="findings",
            path=paths.get("findings.json", ""),
            great_findings=findings["counts"]["great"],
            manual_check_findings=findings["counts"]["manual"],
            rejected_noise=findings["counts"]["rejected"],
        )
        return findings
