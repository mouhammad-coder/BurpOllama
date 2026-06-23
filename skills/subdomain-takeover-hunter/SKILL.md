---
name: subdomain-takeover-hunter
description: Hunts for dangling DNS records and subdomain takeover misconfigurations on authorized assets only, producing manually verified, low-false-positive findings with strong evidence. Use when the user asks to test, audit, or build methodology for subdomain takeover on a domain they own, have written authorization for, or that is in a public bug bounty / VDP scope. Also use for defensive dangling-DNS audits and report templating.
icon: shield-alert
color: Red
related_server_ids:
- firecrawl
---

# Subdomain Takeover Hunter

## Purpose

Hunt for dangling DNS records and takeover-risk misconfigurations **only on authorized assets**. The goal is not a high finding count — it is accurate, manually verified, low-false-positive reports backed by reproducible evidence.

## Hard Safety Rules (read first, every run)

Before ANY recon, confirm one of these is true:

1. The user owns the domain.
2. The user has written authorization.
3. The domain is in a public bug bounty or VDP scope.
4. The user wants methodology only, not a live scan.

Then enforce:

- Never test random companies, unrelated domains, or out-of-scope assets.
- Never claim, register, bind, or take over a third-party resource **unless** program rules explicitly allow proof-of-control. Otherwise stop at non-destructive validation.
- Never host phishing, credential forms, malware, redirectors, tracking pixels, or brand-impersonation content.
- Never access private data, cookies, sessions, internal panels, or user content via a takeover.
- If takeover looks possible, collect **safe proof only**.

Full refusal conditions and safe alternatives: see `references/safety.md`.

## Environment & Tooling Assumptions

This sandbox is **not** a kitted-out recon box. Before assuming a CLI exists, check it (`which subfinder dnsx httpx dig nuclei openssl curl 2>/dev/null`).

- Almost always available: `curl`, `openssl`, Python (`requests`, `dnspython` if installed).
- Often missing: `subfinder`, `chaos`, `dnsx`, `httpx`, `nuclei`, `dig`. Install via `pip`/binary download only if the user authorizes active scanning, or fall back to passive HTTP/CT-log evidence.
- `firecrawl` (connected) can fetch CT-log / passive-DNS web pages and provider error pages for evidence when CLIs are unavailable.

State your tooling limits to the user up front rather than emitting commands you cannot run.

## Workflow

Track progress with this checklist:

```
Takeover Hunt Progress:
- [ ] Phase 0: Authorization + scope confirmed
- [ ] Phase 1: Scope table built
- [ ] Phase 2: Passive enumeration
- [ ] Phase 3: DNS + HTTP + TLS enrichment
- [ ] Phase 4: Candidate detection
- [ ] Phase 5: Manual validation + classification
- [ ] Phase 6: Proof (non-destructive unless authorized)
- [ ] Phase 7: Evidence artifacts + report
```

### Phase 0: Authorization & Inputs

Ask the user for: target root domain or program name, proof of authorization / program URL, in-scope and out-of-scope domains, whether active HTTP probing is allowed, whether proof-of-control claiming is allowed, and any rate limits. Do not proceed until scope is unambiguous.

### Phase 1: Scope Validation

Build a scope table; never scan anything marked Unknown or Out of Scope.

| Asset | Source | In Scope? | Notes |
|---|---|---:|---|
| example.com | User / Program page | Yes | Root domain |
| dev.example.com | Program page | Yes | Subdomain allowed |
| thirdparty.example.net | Unknown | No | Exclude until confirmed |

### Phase 2: Passive Enumeration

Collect candidates from **multiple independent sources** (passive first). Current, working sources:

- **CT logs:** crt.sh, CertSpotter, Censys certificates
- **Passive DNS:** SecurityTrails, VirusTotal relations, AlienVault OTX
- **Datasets/search:** Chaos (ProjectDiscovery), Shodan, Censys hosts, GitHub code search, Wayback Machine, CommonCrawl
- **Business intel:** acquisitions, old brands, subsidiaries, retired product names

> Deprecated — do NOT rely on these (dead/discontinued): BufferOver, Crobat, Rapid7 Open Data FDNS. Skip them.

Tooling (only if installed/authorized), then normalize:

```bash
subfinder -d example.com -all -recursive -o subs.subfinder.txt
chaos -d example.com -silent -o subs.chaos.txt
cat subs.*.txt | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sed 's/\.$//' | sort -u > subdomains.all.txt
```

### Phase 3: Enrichment

For every subdomain, gather DNS + HTTP + TLS evidence and record: CNAME, A/AAAA, HTTP status/title/server header, body fingerprint, TLS subject/issuer/SANs, error message, redirect chain, timestamp, discovery source. Exact commands: see `references/commands.md`.

### Phase 4: Candidate Detection

Flag as a candidate if one or more hold:

1. CNAME → third-party service showing an unclaimed-resource fingerprint.
2. CNAME → deleted/expired/non-existent host.
3. A/AAAA → service returning default/placeholder/404/502/NXDOMAIN-like/unconfigured-tenant content.
4. HTTP shows a known service-specific unclaimed message.
5. TLS cert shows default/placeholder/shared/unrelated tenant identity.
6. Historical DNS shows stale SaaS mappings.
7. GitHub/Wayback/CommonCrawl evidence shows a now-deleted external app.

**Single signals are never enough.** 404 alone, 502 alone, connection-refused alone, or a default cert alone do NOT qualify. Require DNS evidence **plus** service-specific evidence.

### Phase 5: Manual Validation & Classification

Confirm DNS → identify provider → match against current fingerprints (`can-i-take-over-xyz`) → check whether the service is takeoverable *today* → rule out known false positives → check program proof-of-control rules. Then classify:

| Status | Meaning |
|---|---|
| Confirmed Vulnerable | Non-destructive evidence proves resource is unclaimed, or authorized proof-of-control succeeded |
| Likely Vulnerable | Strong DNS + fingerprint evidence, but claiming not allowed |
| Needs Confirmation | Provider behavior ambiguous |
| False Positive | Configured, protected, intentionally parked, or not takeoverable |
| Out of Scope | Not authorized |

### Phase 6: Proof Rules

Acceptable (always): DNS/CNAME/A evidence, HTTP error fingerprint, TLS mismatch, historical evidence, provider/fingerprint-DB match, screenshot of safe error page, `curl`/`dig` output, timestamps.

Only if **explicitly authorized**: claiming the external resource, binding the hostname, hosting a harmless proof token. Template in `references/proof.md`. Never claim when rules are unclear.

### Phase 7: Evidence Artifacts & Report

Produce one evidence block per finding and a final report. Use the templates in `references/templates.md` (evidence block, candidate table, source-coverage table, and full markdown report). After hunting, deliver: executive summary, scope table, source-coverage table, candidate table, confirmed/likely findings, rejected false positives (with reasons), reproduction commands, impact assessment, remediation plan, and a raw-evidence appendix.

## Intelligence-First Rules

Do not blindly trust tools. Compare present vs historical DNS; hunt acquisitions and old product names; check GitHub for old deploy config and Wayback for old hosted apps; verify whether the provider changed takeover behavior or requires exact tenant names; distinguish generic vs service-specific error pages; account for wildcard DNS, DNSSEC, CDN, WAF, and parking; confirm CNAME chains end at a real configured tenant; query multiple resolvers. **A valid report must survive manual review.**

## Impact Assessment

Assess realistic impact only — do not exaggerate. Criteria and the Critical→Informational scale are in `references/impact.md`.

## References

- `references/safety.md` — full refusal conditions and safe alternatives
- `references/commands.md` — exact dig/curl/openssl/resolver commands
- `references/templates.md` — evidence block, tables, and full report template
- `references/proof.md` — authorized proof-of-control token format
- `references/impact.md` — impact criteria and severity scale
