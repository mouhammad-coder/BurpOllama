"""Passive access-control candidate identification."""

import re

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class AccessControlAgent(BaseAgent):
    name = "access-control"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        candidates = []
        for url in context.recon.get("urls", []):
            if re.search(r"(?:/|=)\d+(?:[/?&#]|$)", url):
                candidates.append(normalize_finding({
                    "source": "passive-access-control-agent",
                    "vuln_type": "IDOR Candidate",
                    "title": "Sequential object identifier observed",
                    "severity": "MEDIUM",
                    "confidence": 45,
                    "url": url,
                    "description": "A numeric object identifier may represent an authorization boundary.",
                    "evidence": "Sequential identifier pattern in discovered URL.",
                    "business_impact": "Unconfirmed; cross-user access could expose another user's data.",
                    "remediation": "Enforce object-level authorization on every request.",
                    "exploitability_status": "needs_manual_validation",
                    "evidence_strength": "weak",
                    "false_positive_risk": "high",
                    "redaction_status": "redacted",
                    "safe_manual_validation_steps": [
                        "Configure Session A and Session B.",
                        "Request the object with its owning session.",
                        "Repeat with the non-owning session and compare responses.",
                    ],
                }, scan_id=context.scan["id"]))
        context.raw_findings.extend(candidates)
        for finding in candidates:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message="IDOR candidate needs Session A/B proof",
                finding=finding,
            )
        return candidates
