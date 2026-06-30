"""Bounded discovery workflows built on safe optional-tool adapters."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from external_tools import ToolResult, run_tool
from scope_policy import scope_policy


@dataclass
class AggregatedScope:
    allowed_assets: set[str] = field(default_factory=set)
    disallowed_assets: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    confirmed: bool = False

    def to_dict(self) -> dict:
        return {
            "allowed_assets": sorted(self.allowed_assets),
            "disallowed_assets": sorted(self.disallowed_assets),
            "sources": self.sources,
            "confirmed": self.confirmed,
            "warning": (
                "Imported scope is advisory until you compare it with the live "
                "program policy and explicitly confirm it."
            ),
        }


def _asset_text(value) -> str:
    if isinstance(value, dict):
        value = (
            value.get("asset_identifier")
            or value.get("asset")
            or value.get("target")
            or value.get("domain")
            or ""
        )
    return str(value or "").strip()


def aggregate_scope_documents(documents: list[tuple[str, str]]) -> dict:
    """Aggregate exported JSON/CSV scope documents without treating them as authority."""
    result = AggregatedScope()
    for source, text in documents:
        result.sources.append(source)
        suffix = Path(source).suffix.lower()
        if suffix == ".csv":
            rows = list(csv.DictReader(io.StringIO(text)))
            for row in rows:
                asset = _asset_text(row)
                eligible = str(
                    row.get("eligible_for_submission")
                    or row.get("eligible")
                    or row.get("in_scope")
                    or "true"
                ).lower() not in {"false", "0", "no"}
                (result.allowed_assets if eligible else result.disallowed_assets).add(asset)
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list):
            payload = {"allowed_assets": payload}
        structured = payload.get("structured_scopes", []) if isinstance(payload, dict) else []
        for item in structured if isinstance(structured, list) else []:
            asset = _asset_text(item)
            if not asset:
                continue
            eligible = True
            if isinstance(item, dict):
                eligible = bool(
                    item.get("eligible_for_submission", item.get("eligible", True))
                )
            (result.allowed_assets if eligible else result.disallowed_assets).add(asset)
        for key in ("allowed_assets", "in_scope", "targets", "assets"):
            for item in payload.get(key, []) if isinstance(payload, dict) else []:
                asset = _asset_text(item)
                if asset:
                    result.allowed_assets.add(asset)
        for key in ("disallowed_assets", "out_of_scope", "excluded"):
            for item in payload.get(key, []) if isinstance(payload, dict) else []:
                asset = _asset_text(item)
                if asset:
                    result.disallowed_assets.add(asset)
    result.allowed_assets.difference_update(result.disallowed_assets)
    return result.to_dict()


def _domain_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return parsed.hostname or ""


async def run_discovery_workflow(
    workflow: str,
    target: str,
    *,
    authorized: bool,
    intensive_authorized: bool = False,
) -> list[ToolResult]:
    """Run a known workflow with conservative arguments and bounded timeouts."""
    workflow = str(workflow or "").lower()
    domain = _domain_from_target(target)
    if not domain:
        return [ToolResult(workflow, [], None, skipped=True, reason="Invalid target.")]
    allowed, reason = scope_policy.validate_target(target, action="active")
    if not allowed:
        return [
            ToolResult(
                workflow,
                [],
                None,
                skipped=True,
                reason="ScopePolicy blocked discovery: {}".format(reason),
            )
        ]
    plans = {
        "cloud": [
            ("cloud_enum", ["-k", domain], 300),
        ],
        "takeover": [
            ("subjack", ["-d", domain, "-ssl"], 180),
            ("dnsreaper", ["single", "--domain", domain], 180),
            ("nuclei", ["-u", target, "-tags", "takeover", "-silent"], 180),
        ],
        "secrets": [
            ("gitleaks", ["detect", "--no-banner", "--redact"], 180),
            ("trufflehog", ["filesystem", ".", "--no-update"], 300),
        ],
        "parameters": [
            ("paramspider", ["-d", domain], 180),
            ("arjun", ["-u", target, "--stable"], 300),
        ],
        "ports": [
            ("naabu", ["-host", domain, "-silent", "-rate", "100"], 180),
            (
                "nmap",
                ["-sV", "--version-light", "-T3", "--top-ports", "100", domain],
                300,
            ),
        ],
        "tls": [
            ("testssl.sh", ["--quiet", "--warnings", "off", target], 300),
        ],
        "cms": [
            ("droopescan", ["scan", "-u", target], 300),
        ],
        "kubernetes": [
            ("kube-hunter", ["--remote", domain, "--report", "json"], 300),
        ],
    }
    results = []
    for name, arguments, timeout in plans.get(workflow, []):
        results.append(
            await run_tool(
                name,
                arguments,
                timeout=timeout,
                authorized=authorized,
                intensive_authorized=intensive_authorized,
            )
        )
    if not results:
        results.append(
            ToolResult(workflow, [], None, skipped=True, reason="Unknown discovery workflow.")
        )
    return results
