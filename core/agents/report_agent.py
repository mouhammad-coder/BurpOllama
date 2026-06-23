"""Report generation and durable export agent."""

from reporter import generate_full_report

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType
from core.reports import write_report_bundle


class ReportAgent(BaseAgent):
    name = "report"
    phase = "report_export"

    async def run(self, context: ScanContext):
        report = await generate_full_report(
            context.scan["target"],
            context.recon,
            context.triaged_findings,
            context.analysis,
            api_key=context.options.api_key,
            scope=context.scope.to_dict(),
            review_items=[
                finding for finding in context.triaged_findings
                if finding.get("verdict") not in {"PASS", "DOWNGRADE"}
            ],
        )
        context.scan["report"] = report
        paths = write_report_bundle(
            context.scan,
            context.options.output,
        )
        context.report_paths = paths
        context.scan["report_paths"] = paths
        for report_format, path in paths.items():
            context.store.save_report(
                context.scan["id"], report_format, path
            )
            await context.emit(
                EventType.REPORT_WRITTEN,
                agent=self.name,
                phase=self.phase,
                message="{} report written".format(report_format),
                format=report_format,
                path=path,
            )
        return paths
