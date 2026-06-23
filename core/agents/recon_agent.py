"""Target probing and bounded reconnaissance agent."""

from __future__ import annotations

import httpx

from adaptive_scan import build_adaptive_plan, profile_target
from finding_model import normalize_finding
from recon_engine import RECON_RATE_LIMITER, run_full_recon

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType
from core.ratelimit import RateLimiter
from core.recon_expansion import (
    build_urls_for_subdomains,
    check_dns_misconfigurations,
    domain_from_target,
    fetch_passive_subdomains,
    fetch_wayback_urls,
    is_ip_address,
)


class ReconAgent(BaseAgent):
    name = "recon"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        profile = await profile_target(context.scan["target"], _ScopeAdapter(context))
        plan = build_adaptive_plan(profile, context.options.internal_mode)
        plan.concurrency = min(plan.concurrency, context.options.concurrency)
        plan.request_timeout = context.options.timeout
        context.scan["target_profile"] = profile.to_dict()
        context.scan["adaptive_plan"] = plan.to_dict()

        async def log(message: str, level: str = "info"):
            await context.log(message, level, agent=self.name, phase=self.phase)

        limiter_token = RECON_RATE_LIMITER.set(context.rate_limiter)
        try:
            recon = await run_full_recon(
                context.scan["target"],
                log,
                adaptive_plan=plan.to_dict(),
                use_external_tools=False,
            )
        finally:
            RECON_RATE_LIMITER.reset(limiter_token)
        await self._expand_passive_recon(context, recon)
        allowed, skipped = context.scope.filter(recon.get("urls", []))
        recon["urls"] = list(dict.fromkeys(allowed or [context.scan["target"]]))
        recon["skipped_out_of_scope"] = skipped
        context.recon = recon
        context.scan["recon"] = recon
        for url in recon["urls"]:
            await context.emit(
                EventType.URL_DISCOVERED,
                agent=self.name,
                phase=self.phase,
                message="Discovered {}".format(url),
                url=url,
            )
        for url in skipped:
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped out-of-scope URL",
                url=url,
                reason="out_of_scope",
            )
        return recon

    async def _expand_passive_recon(self, context: ScanContext, recon: dict) -> None:
        domain = domain_from_target(context.scan["target"])
        if not domain or is_ip_address(domain):
            recon.setdefault("passive_subdomains", [])
            recon.setdefault("wayback_urls", [])
            recon.setdefault("dns_findings", [])
            return

        passive_limiter = RateLimiter(requests_per_second=1 / 3, max_requests=20)
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            headers={"User-Agent": "BurpOllama Passive Recon"},
        ) as client:
            subdomain_result = await fetch_passive_subdomains(domain, client, passive_limiter)
            scoped_subdomains = [
                host for host in subdomain_result.get("subdomains", [])
                if context.scope.allows("https://" + host)
            ]
            recon["passive_subdomains"] = scoped_subdomains
            recon.setdefault("subdomains", [])
            recon["subdomains"] = list(dict.fromkeys((recon.get("subdomains") or []) + scoped_subdomains))
            recon.setdefault("passive_recon_errors", {}).update(subdomain_result.get("errors", {}))

            subdomain_urls = build_urls_for_subdomains(scoped_subdomains, scheme="https")
            wayback_result = await fetch_wayback_urls(
                domain,
                client,
                passive_limiter,
                context.scope.allows,
            )
            wayback_urls = wayback_result.get("urls", [])
            recon["wayback_urls"] = wayback_urls
            recon.setdefault("passive_recon_errors", {}).update(wayback_result.get("errors", {}))
            recon["urls"] = list(dict.fromkeys((recon.get("urls") or []) + subdomain_urls + wayback_urls))

        dns_findings = await check_dns_misconfigurations(domain, scoped_subdomains)
        recon["dns_findings"] = [finding.__dict__ for finding in dns_findings]
        raw_findings = []
        for dns_finding in dns_findings:
            raw_findings.append(self._dns_to_finding(context, dns_finding))
        if raw_findings:
            context.raw_findings.extend(raw_findings)
            context.scan["raw_findings"] = context.raw_findings
            for finding in raw_findings:
                context.scheduler.state(self.name).findings += 1
                await context.emit(
                    EventType.FINDING_CANDIDATE,
                    agent=self.name,
                    phase=self.phase,
                    message=finding.get("title", "DNS recon finding"),
                    finding=finding,
                )

    def _dns_to_finding(self, context: ScanContext, dns_finding) -> dict:
        url = "https://{}".format(dns_finding.host)
        if dns_finding.kind == "dangling_cname_candidate":
            title = "Dangling CNAME takeover candidate"
            severity = "MEDIUM"
            description = "A subdomain CNAME points at an external service and needs non-destructive takeover validation."
            indicator = ", ".join(dns_finding.cname_chain) or dns_finding.evidence
            location = "DNS CNAME chain"
            impact = "Dangling external-service CNAMEs can indicate possible subdomain takeover if the provider resource is unclaimed."
        else:
            title = "Missing {} DNS policy".format("SPF" if dns_finding.kind == "missing_spf" else "DMARC")
            severity = "INFO"
            description = dns_finding.evidence
            indicator = dns_finding.evidence
            location = "DNS TXT records"
            impact = "Missing email authentication policy may increase spoofing risk."
        artifact = write_evidence_artifact(
            context.scan,
            title=title,
            url=url,
            raw_request="DNS query for {}".format(dns_finding.host),
            raw_response="kind={}; evidence={}; cname_chain={}; ttl={}".format(
                dns_finding.kind,
                dns_finding.evidence,
                dns_finding.cname_chain,
                dns_finding.ttl,
            ),
            matched_indicator=indicator,
            indicator_location=location,
            agent=self.name,
            vuln_class=title,
            impact=impact,
            fp_check="Passive DNS observation only; requires manual validation before confirmation.",
            confirmed=False,
            filename_prefix="dns",
            metadata={
                "dns_kind": dns_finding.kind,
                "ttl": dns_finding.ttl,
                "cname_chain": dns_finding.cname_chain,
            },
        )
        return normalize_finding({
            "source": "passive-dns-recon",
            "vuln_type": title,
            "title": title,
            "severity": severity,
            "confidence": 70 if dns_finding.kind == "dangling_cname_candidate" else 50,
            "url": url,
            "method": "DNS",
            "description": description,
            "evidence": indicator,
            "evidence_artifact": artifact,
            "business_impact": impact,
            "reproduction_steps": [
                "Query DNS records for {}.".format(dns_finding.host),
                "Inspect returned CNAME/TXT evidence.",
                "Perform only non-destructive validation inside authorized scope.",
            ],
            "remediation": "Remove stale records or configure the appropriate DNS policy.",
            "cwe": "CWE-200",
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "medium",
            "redaction_status": "redacted",
        }, scan_id=context.scan["id"])


class _ScopeAdapter:
    def __init__(self, context: ScanContext):
        self.context = context

    def validate_target(self, target: str, action: str = "scan"):
        return (
            (True, "Allowed by CLI scope")
            if self.context.scope.allows(target)
            else (False, "Outside CLI scope")
        )

    def record_request(self, target: str, action: str = "scan"):
        if not self.context.scope.allows(target):
            return False, "Outside CLI scope"
        # The adaptive profiler is intentionally tiny; the main hunt path uses
        # the shared asynchronous limiter.
        return True, "Allowed by CLI scope"
