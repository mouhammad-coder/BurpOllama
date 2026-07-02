## Unreleased

- Added final-findings model with Great Findings and Needs Manual Check terminal output.
- Added goal-based `ai-autopilot` workflow.
- Added `program.yml` scope and permission enforcement.
- Added passive Burp import and Burp import analysis.
- Added `preflight` command for scope, permission, rate-limit, and mode checks.
- Added `--dry-run-plan` for no-request scan planning.
- Added local lab and benchmark validation paths.
- Removed report generation from the primary user workflow; final findings are printed directly.

## v1.4
- CLI bug bounty workflow verified on an explicitly authorized live program target
- `scope-check --audit` now emits a CLI runbook for safe passive scan and findings review
- `findings --latest` and `history --ready-only` shortcuts for faster finding triage
- Final findings show missing evidence artifact counts and artifact availability
- Deprecated compatibility checks now direct users to final findings
- Final scan output now includes a compact bounty findings table in the terminal
- Evidence artifacts are ignored by default so private scan data is not committed accidentally
- All v1.3 features included

## v1.3
- GraphQL passive observation and introspection check
- File upload endpoint passive detection
- All v1.2 features included

## v1.2
- Access control: IDOR candidates, auth coverage gaps
- Rate limit: passive observation + safe 5-request probe
- SSRF: passive parameter detection + OOB stub
- CORS: misconfiguration detection including * + credentials
- Open redirect: passive parameter observation
- Legacy marketplace text helpers retained only for compatibility
- External tools: Katana, Nuclei, TruffleHog, Gitleaks wrappers
- All v1.1 features included

## v1.1
- Access control passive observation: IDOR candidates, auth coverage gaps, HTTP method observations
- Rate limit passive observation and safe 5-request probe
- All v1.0 features included

## v1.0
- Passive auth observation: JWT, cookie flags, OAuth redirect_uri
- Local AI feedback loop: burpollama train
- Scope file support: HackerOne/Bugcrowd wildcard scope blocks
- burpollama scope-check utility
- All v1.0-beta features included

## v1.0-beta
- CLI-first scanner with Rich terminal UI
- Passive / bounty / deep scan modes
- Multi-agent architecture (11 agents)
- Strict proof gate: findings confirmed only with full evidence artifacts
- Generic evidence agents: header, SQLi, XSS, exposed paths
- Passive recon: crt.sh, Wayback, JS secrets, DNS checks
- Local Ollama AI triage (reads artifacts, never overrides gate)
- Modular skill system
- Subdomain Takeover Hunter skill with real-world corpus
- Benchmark mode isolated from normal scan path
- 160+ offline tests passing
