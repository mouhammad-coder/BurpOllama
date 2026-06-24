## v1.2
- Access control: IDOR candidates, auth coverage gaps
- Rate limit: passive observation + safe 5-request probe
- SSRF: passive parameter detection + OOB stub
- CORS: misconfiguration detection including * + credentials
- Open redirect: passive parameter observation
- Report export: HackerOne and Bugcrowd markdown format
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
