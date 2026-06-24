"""JavaScript endpoint and hidden-route intelligence agent."""

from pathlib import Path

from finding_model import normalize_finding
from recon_intelligence import advanced_recon_intelligence

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType
from core.recon_expansion import extract_js_intelligence


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


class JavaScriptAgent(BaseAgent):
    name = "javascript"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        live_hosts = [
            item.get("url", "")
            for item in context.recon.get("live_hosts", [])
            if isinstance(item, dict)
        ]
        intelligence = await advanced_recon_intelligence(
            context.scan["target"],
            context.recon.get("urls", []),
            context.recon.get("js_contents", {}),
            live_hosts,
            context.recon.get("tech_stack", []),
        )
        context.recon["intelligence"] = intelligence
        for url in intelligence.get("hidden_endpoints", [])[:100]:
            if context.scope.allows(url):
                await context.emit(
                    EventType.URL_DISCOVERED,
                    agent=self.name,
                    phase=self.phase,
                    message="JavaScript endpoint {}".format(url),
                    url=url,
                    source="javascript",
                )
        findings = self._extract_js_candidate_findings(context)
        if findings:
            context.raw_findings.extend(findings)
            context.scan["raw_findings"] = context.raw_findings
            for finding in findings:
                context.scheduler.state(self.name).findings += 1
                await context.emit(
                    EventType.FINDING_CANDIDATE,
                    agent=self.name,
                    phase=self.phase,
                    message=finding.get("title", "JavaScript finding"),
                    finding=finding,
                )
        return intelligence

    def _extract_js_candidate_findings(self, context: ScanContext) -> list[dict]:
        findings: list[dict] = []
        js_contents = context.recon.get("js_contents", {}) or {}
        if not isinstance(js_contents, dict):
            return findings
        for js_url, content in js_contents.items():
            if not isinstance(content, str) or not context.scope.allows(str(js_url)):
                continue
            extracted = extract_js_intelligence(content)
            findings.extend(self._secret_findings(context, str(js_url), content, extracted.get("secrets", [])))
            findings.extend(self._generic_js_indicator_findings(
                context,
                str(js_url),
                content,
                "S3 Bucket Reference in JavaScript",
                "s3_bucket_reference",
                extracted.get("s3_buckets", []),
                "S3 bucket references in client-side JavaScript can reveal storage assets for authorization review.",
            ))
            findings.extend(self._generic_js_indicator_findings(
                context,
                str(js_url),
                content,
                "Internal Host Reference in JavaScript",
                "internal_host_reference",
                extracted.get("internal_hosts", []),
                "Internal host/IP references in public JavaScript can reveal internal architecture or staging endpoints.",
            ))
        return findings

    def _secret_findings(self, context: ScanContext, js_url: str, content: str, secrets: list[dict]) -> list[dict]:
        findings = []
        for secret in secrets[:25]:
            offset = int(secret.get("offset") or 0)
            snippet = content[max(0, offset - 80): offset + 160]
            artifact = write_evidence_artifact(
                context.scan,
                title="Possible Secret in JavaScript",
                url=js_url,
                raw_request="GET {} HTTP/1.1".format(js_url),
                raw_response=snippet,
                matched_indicator=str(secret.get("matched_indicator") or secret.get("name") or "secret assignment"),
                indicator_location="JavaScript source offset {}".format(offset),
                agent=self.name,
                vuln_class="JavaScript Secret Candidate",
                impact="Client-side keys or tokens may expose third-party services if valid and insufficiently restricted.",
                fp_check="Pattern is a passive candidate only; value is redacted and must be manually validated.",
                confirmed=False,
                filename_prefix="javascript",
                metadata={
                    "name": secret.get("name"),
                    "value_preview": secret.get("value_preview"),
                    "offset": offset,
                },
            )
            findings.append(normalize_finding({
                "source": "javascript-agent",
                "vuln_type": "JavaScript Secret Candidate",
                "title": "Possible Secret in JavaScript",
                "severity": "MEDIUM",
                "confidence": 65 if _artifact_saved(artifact) else 35,
                "url": js_url,
                "method": "GET",
                "description": "A key/token/secret-looking assignment was found in a JavaScript asset.",
                "evidence": "{} at offset {}".format(secret.get("name"), offset),
                "evidence_artifact": artifact,
                "business_impact": "Potential credential exposure requires manual validation and safe rotation guidance.",
                "reproduction_steps": [
                    "Fetch the JavaScript asset.",
                    "Search for key/token/secret assignments.",
                    "Validate safely without using the credential against live services unless authorized.",
                ],
                "remediation": "Remove secrets from client-side code and rotate any exposed values.",
                "cwe": "CWE-798",
                "exploitability_status": "needs_manual_validation",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings

    def _generic_js_indicator_findings(
        self,
        context: ScanContext,
        js_url: str,
        content: str,
        title: str,
        vuln_type: str,
        indicators: list[dict],
        impact: str,
    ) -> list[dict]:
        findings = []
        for item in indicators[:25]:
            value = str(item.get("value") or "")
            offset = int(item.get("offset") or 0)
            snippet = content[max(0, offset - 80): offset + 160]
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=js_url,
                raw_request="GET {} HTTP/1.1".format(js_url),
                raw_response=snippet,
                matched_indicator=value,
                indicator_location="JavaScript source offset {}".format(offset),
                agent=self.name,
                vuln_class=title,
                impact=impact,
                fp_check="Passive client-side reference only; requires manual validation before impact claims.",
                confirmed=False,
                filename_prefix="javascript",
                metadata={"offset": offset},
            )
            findings.append(normalize_finding({
                "source": "javascript-agent",
                "vuln_type": vuln_type,
                "title": title,
                "severity": "LOW",
                "confidence": 60 if _artifact_saved(artifact) else 30,
                "url": js_url,
                "method": "GET",
                "description": "A noteworthy reference was found in a JavaScript asset.",
                "evidence": value,
                "evidence_artifact": artifact,
                "business_impact": impact,
                "reproduction_steps": [
                    "Fetch the JavaScript asset.",
                    "Locate the referenced indicator.",
                    "Review authorization and exposure manually.",
                ],
                "remediation": "Remove unnecessary public references or restrict referenced assets appropriately.",
                "cwe": "CWE-200",
                "exploitability_status": "needs_manual_validation",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings
