"""Evidence artifacts for skill runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_EVIDENCE_KEYS = {
    "target_subdomain",
    "root_domain",
    "scope_status",
    "discovery_source",
    "dns_evidence",
    "http_evidence",
    "tls_evidence",
    "provider_fingerprint",
    "false_positive_checks",
    "proof_of_control_allowed",
    "proof_performed",
    "reproduction_commands",
    "timestamp",
    "final_status",
}


def validate_evidence_schema(item: dict[str, Any]) -> tuple[bool, list[str]]:
    missing = sorted(key for key in REQUIRED_EVIDENCE_KEYS if key not in item)
    return not missing, missing


class SkillEvidenceWriter:
    def __init__(self, run_dir: Path | str):
        self.run_dir = Path(run_dir)
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def write_raw(self, name: str, content: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name)
        path = self.raw_dir / safe
        path.write_text(content or "", encoding="utf-8", errors="replace")
        return str(path)

    def build_record(
        self,
        *,
        target_subdomain: str,
        root_domain: str,
        scope_status: str,
        discovery_source: str,
        dns_evidence: dict[str, Any],
        http_evidence: dict[str, Any],
        tls_evidence: dict[str, Any],
        provider_fingerprint: dict[str, Any],
        false_positive_checks: list[str],
        proof_of_control_allowed: bool,
        proof_performed: bool,
        reproduction_commands: list[str],
        final_status: str,
    ) -> dict[str, Any]:
        return {
            "target_subdomain": target_subdomain,
            "root_domain": root_domain,
            "scope_status": scope_status,
            "discovery_source": discovery_source,
            "dns_evidence": dns_evidence,
            "http_evidence": http_evidence,
            "tls_evidence": tls_evidence,
            "provider_fingerprint": provider_fingerprint,
            "false_positive_checks": false_positive_checks,
            "proof_of_control_allowed": proof_of_control_allowed,
            "proof_performed": proof_performed,
            "reproduction_commands": reproduction_commands,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "final_status": final_status,
        }

    def write_bundle(self, records: list[dict[str, Any]]) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "evidence.json").write_text(
            json.dumps({"evidence": records}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        findings = []
        for index, item in enumerate(records, start=1):
            provider = item.get("provider_fingerprint", {}).get("provider", "unknown")
            findings.append({
                "id": "skill-finding-{}".format(index),
                "title": "Subdomain takeover candidate",
                "status": "Needs Manual Check",
                "rate": "High",
                "confidence": 70 if item.get("final_status") == "candidate" else 40,
                "affected_asset": item.get("target_subdomain", ""),
                "evidence": "DNS, HTTP, and TLS evidence captured for provider {}".format(provider),
                "missing_proof": "Proof-of-control was not performed",
                "manual_check_needed": (
                    "Confirm the program permits proof-of-control, then safely claim "
                    "the dangling resource with an authorized marker only."
                ),
            })
        (self.run_dir / "findings.json").write_text(
            json.dumps({"findings": findings}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
