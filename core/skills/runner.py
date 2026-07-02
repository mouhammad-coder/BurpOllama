"""Run skills explicitly from the CLI."""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from core.skills.evidence import SkillEvidenceWriter
from core.skills.knowledge_base import SkillKnowledgeBase
from core.skills.loader import ROOT, Skill
from core.scope import is_in_scope


RUNS_ROOT = ROOT / "runs" / "skills"


@dataclass
class SkillRunOptions:
    target: str
    mode: str = "passive"
    scope: list[str] | None = None
    authorization_confirmed: bool = False
    scope_confirmed: bool = False
    active_permission: bool = False
    proof_of_control_allowed: bool = False
    proof_of_control_confirmed: bool = False
    output_root: Path | str = RUNS_ROOT
    timeout: float = 8.0


class SkillSafetyError(PermissionError):
    pass


def normalize_domain(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else "http://" + value)
    return (parsed.hostname or value).strip(".").lower()


def _run_slug(skill_name: str, target: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in target)
    return "{}-{}".format(
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        safe[:80] or skill_name,
    )


class SkillRunner:
    def __init__(self, knowledge: SkillKnowledgeBase | None = None):
        self.knowledge = knowledge or SkillKnowledgeBase()

    def safety_gate(self, skill: Skill, options: SkillRunOptions) -> None:
        target = normalize_domain(options.target)
        if not target:
            raise SkillSafetyError("target domain is required")
        if not options.authorization_confirmed:
            raise SkillSafetyError("authorization confirmation is required")
        if not options.scope_confirmed:
            raise SkillSafetyError("scope confirmation is required")
        scope = list(options.scope or [target])
        in_scope, _warnings = is_in_scope(target, scope)
        if not in_scope:
            raise SkillSafetyError("target is out of confirmed scope")
        mode = str(options.mode or "passive").lower()
        if mode not in skill.supported_modes:
            raise SkillSafetyError("unsupported mode for skill: {}".format(mode))
        if mode == "validate" and not options.active_permission:
            raise SkillSafetyError("validate mode requires active probing permission")
        if options.proof_of_control_allowed and not options.proof_of_control_confirmed:
            raise SkillSafetyError(
                "proof-of-control requires explicit confirmation and program permission"
            )

    async def run(self, skill: Skill, options: SkillRunOptions) -> dict[str, Any]:
        self.safety_gate(skill, options)
        if skill.name != "subdomain-takeover-hunter":
            raise RuntimeError("No runner implemented for skill: {}".format(skill.name))
        target = normalize_domain(options.target)
        run_dir = Path(options.output_root) / skill.name / _run_slug(skill.name, target)
        writer = SkillEvidenceWriter(run_dir)
        knowledge, cache_hit = self.knowledge.load(skill.name)
        record = await self._run_subdomain_takeover(
            target,
            options,
            writer,
            knowledge,
        )
        writer.write_bundle([record])
        return {
            "skill": skill.name,
            "target": target,
            "mode": options.mode,
            "run_dir": str(run_dir),
            "cache_hit": cache_hit,
            "warning": "" if cache_hit else "knowledge cache missing; used bundled safe fingerprints",
            "records": [record],
            "evidence_path": str(run_dir / "evidence.json"),
            "findings_path": str(run_dir / "findings.json"),
        }

    async def _run_subdomain_takeover(
        self,
        target: str,
        options: SkillRunOptions,
        writer: SkillEvidenceWriter,
        knowledge: dict[str, Any],
    ) -> dict[str, Any]:
        dns = await asyncio.to_thread(self._dns_evidence, target)
        http = await self._http_evidence(target, options.timeout)
        tls = await asyncio.to_thread(self._tls_evidence, target, options.timeout)
        dns_raw = writer.write_raw("dns-{}.json".format(target), repr(dns))
        http_raw = writer.write_raw("http-{}.txt".format(target), http.get("raw", ""))
        tls_raw = writer.write_raw("tls-{}.txt".format(target), tls.get("raw", ""))
        provider = self._match_provider(dns, http, knowledge)
        status, fp_checks = self._classify(provider, dns, http)
        record = writer.build_record(
            target_subdomain=target,
            root_domain=target,
            scope_status="in_scope",
            discovery_source="user-supplied target",
            dns_evidence={**dns, "raw_file": dns_raw},
            http_evidence={k: v for k, v in http.items() if k != "raw"} | {"raw_file": http_raw},
            tls_evidence={**tls, "raw_file": tls_raw},
            provider_fingerprint=provider,
            false_positive_checks=fp_checks,
            proof_of_control_allowed=bool(options.proof_of_control_allowed),
            proof_performed=False,
            reproduction_commands=[
                "dig +short CNAME {}".format(target),
                "curl -i -L --max-time 10 https://{}".format(target),
                "openssl s_client -connect {0}:443 -servername {0}".format(target),
            ],
            final_status=status,
        )
        return record

    def _dns_evidence(self, target: str) -> dict[str, Any]:
        evidence: dict[str, Any] = {"hostname": target, "addresses": [], "cname": ""}
        try:
            infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
            evidence["addresses"] = sorted({item[4][0] for item in infos})
        except OSError as exc:
            evidence["error"] = "{}: {}".format(type(exc).__name__, exc)
        try:
            canonical, aliases, _addresses = socket.gethostbyname_ex(target)
            aliases = aliases or []
            if canonical and canonical != target:
                evidence["cname"] = canonical
            evidence["aliases"] = aliases
        except OSError:
            evidence.setdefault("aliases", [])
        return evidence

    async def _http_evidence(self, target: str, timeout: float) -> dict[str, Any]:
        urls = ["https://{}".format(target), "http://{}".format(target)]
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "BurpOllama Skill Runner"},
        ) as client:
            for url in urls:
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                body = response.text[:2000]
                headers = dict(response.headers)
                raw = "HTTP/1.1 {}\n{}\n\n{}".format(
                    response.status_code,
                    "\n".join("{}: {}".format(k, v) for k, v in headers.items()),
                    body,
                )
                return {
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "headers": {
                        key: value
                        for key, value in headers.items()
                        if key.lower() in {"server", "content-type", "location"}
                    },
                    "body_snippet": body[:500],
                    "raw": raw,
                }
        return {"url": urls[0], "status_code": None, "headers": {}, "body_snippet": "", "raw": ""}

    def _tls_evidence(self, target: str, timeout: float) -> dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as tls:
                    cert = tls.getpeercert() or {}
            subject = cert.get("subject", [])
            issuer = cert.get("issuer", [])
            raw = "subject={}\nissuer={}\nnotBefore={}\nnotAfter={}".format(
                subject,
                issuer,
                cert.get("notBefore", ""),
                cert.get("notAfter", ""),
            )
            return {
                "subject": subject,
                "issuer": issuer,
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "raw": raw,
            }
        except Exception as exc:
            return {
                "error": "{}: {}".format(type(exc).__name__, exc),
                "raw": "{}: {}".format(type(exc).__name__, exc),
            }

    def _match_provider(
        self,
        dns: dict[str, Any],
        http: dict[str, Any],
        knowledge: dict[str, Any],
    ) -> dict[str, Any]:
        dns_text = " ".join(
            str(value)
            for value in [
                dns.get("cname", ""),
                " ".join(dns.get("aliases", []) or []),
            ]
        ).lower()
        body = str(http.get("body_snippet", "")).lower()
        for provider in knowledge.get("providers", []):
            cname_hit = any(
                pattern.lower() in dns_text
                for pattern in provider.get("cname_patterns", [])
            )
            http_hit = any(
                pattern.lower() in body
                for pattern in provider.get("http_fingerprints", [])
            )
            if cname_hit or http_hit:
                return {
                    "provider": provider.get("name", "unknown"),
                    "cname_match": cname_hit,
                    "http_match": http_hit,
                    "matched_patterns": provider,
                }
        return {
            "provider": "unknown",
            "cname_match": False,
            "http_match": False,
            "matched_patterns": {},
        }

    def _classify(
        self,
        provider: dict[str, Any],
        dns: dict[str, Any],
        http: dict[str, Any],
    ) -> tuple[str, list[str]]:
        checks = []
        if provider.get("provider") == "unknown":
            checks.append("no known takeover provider fingerprint matched")
            return "Needs Confirmation", checks
        if provider.get("cname_match"):
            checks.append("provider CNAME pattern matched")
        if provider.get("http_match"):
            checks.append("provider-specific HTTP unclaimed fingerprint matched")
        if dns.get("addresses"):
            checks.append("DNS resolves to at least one address")
        if provider.get("cname_match") and provider.get("http_match"):
            return "Likely Vulnerable", checks
        return "Needs Confirmation", checks
