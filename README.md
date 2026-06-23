# BurpOllama

<p align="center">
  <img src="https://img.shields.io/badge/Python-89.6%25-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-Private-red?style=for-the-badge" alt="Private License">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-black?style=for-the-badge&logo=linux" alt="Kali Linux">
  <img src="https://img.shields.io/badge/AI-Local%20%2B%20Cloud-green?style=for-the-badge" alt="Local and Cloud AI">
  <img src="https://img.shields.io/badge/Classes-39%20Vuln%20Classes-orange?style=for-the-badge" alt="39 Vulnerability Classes">
</p>

<p align="center">
<b>CLI-first authorized security scanner with live request streaming, 39 vulnerability
classes, optional AI triage, proof validation, and bounty-ready reports.</b>
</p>

---

## Terminal First

BurpOllama now puts the terminal first. Start an authorized scan and watch the
reconnaissance, tested URLs, HTTP responses, vulnerability classes, throttle
events, errors, and findings as they happen:

```bash
python3 cli.py scan https://target.example
```

Or use the installed launcher:

```bash
burpollama scan https://target.example
```

```text
╔════════════════════════════════════════════════════════╗
║ BurpOllama — Authorized Security Scanner               ║
╚════════════════════════════════════════════════════════╝
Target: https://target.example
Mode:   Bounty Scan

──────────────────── PHASE 1 — RECONNAISSANCE ────────────────────
[19:31:01] ✓ Direct probe: https://target.example → HTTP 200
[19:31:02] → Crawling: https://target.example/api/users
[19:31:03] ✓ Found: /admin → 403

────────────────── PHASE 2 — VULNERABILITY HUNT ──────────────────
[19:31:10] Testing [1/50] SQL Injection...
[19:31:10] → Testing URL 1/47 https://target.example/api/users
[19:31:11] GET https://target.example/api/users → HTTP 200
[19:31:15] Testing [20/50] Security Headers...
[19:31:16] ⚠ FINDING: Missing Content-Security-Policy

────────────────────────── RESULTS ───────────────────────────────
✓ Scan complete in 4m 32s
  HIGH: 2  MEDIUM: 5  LOW: 3  INFO: 8
```

The web dashboard remains available as a companion interface at
`http://127.0.0.1:8888/ui`.

## What It Does

BurpOllama runs locally and:

- Discovers attack surface automatically
- Streams every scan phase, tested URL, and key response to the terminal
- Tests 39 specialized vulnerability classes
- Confirms findings with actual proof (not just detection)
- Scores findings with official CVSS 4.0 and business-aware impact scoring
- Builds exploit chains connecting related vulnerabilities
- Exports HackerOne, Bugcrowd, Markdown, JSON, CSV, and SARIF reports
- Works with Ollama, Gemini, OpenAI, Anthropic, other compatible providers, or no AI

**No mandatory cloud dependency. No mandatory AI key. Runs on your machine.**

> Use BurpOllama only on systems you own or have explicit written authorization to test.

---

## CLI Commands

| Command | Purpose |
|---|---|
| `burpollama scan <target>` | Start a bounty scan and stream it live |
| `burpollama scan <target> --mode passive` | Safe passive-only scan |
| `burpollama scan <target> --mode deep` | Deep authorized scan |
| `burpollama recon <target>` | Run reconnaissance directly |
| `burpollama watch --scan-id <id>` | Watch a dashboard/API scan through WebSocket |
| `burpollama status` | Check backend, database, and AI readiness |
| `burpollama history` | List scans held by the running backend |
| `burpollama report --scan-id <id>` | Print the completed report |
| `burpollama report --scan-id <id> --format hackerone` | Export HackerOne format |
| `burpollama validate "IDOR on /api/users/{id}"` | Classify a finding candidate |
| `burpollama analyze --file traffic.json` | Analyze captured Burp traffic |

The CLI asks for authorization confirmation before active scanning. For
non-interactive use on an explicitly authorized target, add `--yes`.

### Dashboard Companion

Run `bash start.sh`, then open
[http://127.0.0.1:8888/ui](http://127.0.0.1:8888/ui). A scan started in the
dashboard can be followed live in another terminal:

```bash
burpollama watch --scan-id <scan-id>
```

---

## Vulnerability Classes (39 Total)

| Category | Classes |
|----------|---------|
| Injection | SQLi, NoSQL, Command, SSTI, CRLF, Host Header |
| XSS | Reflected, Stored, DOM, Blind |
| Access Control | IDOR/BOLA, BFLA, Auth Bypass, Privilege Escalation |
| Authentication | JWT attacks, OAuth flows, Session security/fixation, Default credentials |
| API Security | Mass assignment, GraphQL auth, API version bypass, Rate limiting |
| Server-Side | SSRF (OOB required), Path traversal/LFI, XXE candidates |
| Client-Side | CSRF, Clickjacking, Browser storage, Prototype pollution, Behavioral anomaly |
| Infrastructure | Subdomain takeover, Secret exposure and validation, Security headers |
| Advanced | WebSocket security, HTTP Request Smuggling, Exploit chain detection, ATO chain analysis |

---

## Key Features

### Zero False Positive Mode

Findings must pass a 12-point proof check before reaching Valid Bugs.
Weak signals stay in Candidates. Only confirmed proof reaches reports.

### CVSS++ Impact Scoring

Goes beyond standard CVSS. Adds business impact, chain bonuses,
exploitability status, and AI confidence adjustment.

### Exploit Chain Builder

Connects individual findings into multi-step attack paths.
IDOR + missing rate limit = Account Takeover chain.
Open redirect + OAuth = Token theft chain.

### Dual-Session IDOR Proof

Configure Session A and Session B cookies.
The tool automatically proves unauthorized cross-session data access.

### OOB Confirmation

SSRF, blind SQLi, blind XSS, and command injection require
interactsh callback confirmation before being marked as confirmed.

### Adaptive Scan Engine

Automatically classifies targets as LIGHT, BALANCED, or DEEP.
Adjusts modules, concurrency, and AI usage based on target complexity.

### AI Privacy Guard

Local Ollama is preferred. Cloud AI is off by default.
Secrets, tokens, and cookies are redacted before any AI analysis.

### Provider-Agnostic AI

Local Ollama, Gemini, Groq, Mistral, DeepSeek, OpenAI, Anthropic, Together,
and custom OpenAI-compatible endpoints with automatic failover.
Includes cost-aware routing, while local models remain free to run.

### Hunter Ecosystem

- Polished `burpollama` terminal CLI
- Nine bounded specialist agent profiles
- Safe optional-tool adapters for recon, validation, discovery, secrets,
  takeover, cloud, WAF, and Web3 tooling
- Advisory JSON/CSV scope aggregation
- Daily fresh-scope monitoring across public HackerOne, Bugcrowd, Intigriti,
  YesWeHack, and Federacy data, with optional ProjectDiscovery Chaos enrichment
- Pheromone-weighted swarm blackboard with decaying signals, independent agent
  trigger predicates, and a live campaign frontier
- Scope-drift enforcement that revalidates authorization between scan phases
- SARIF 2.1 export for GitHub code scanning and CI security dashboards
- Persistent SQLite technique and outcome memory
- Evidence-driven WSTG / API / bug-bounty playbook planning with next-best
  test recommendations and coverage gaps
- Static Solidity candidate analysis
- Harness guidance for Claude Code, Codex, and OpenCode
- Community issue templates, contribution guidance, and security policy

See [CLI](docs/CLI.md), [agents](docs/AGENTS.md),
[external tools](docs/EXTERNAL_TOOLS.md), and [Web3](docs/WEB3.md).

---

## Quick Start on Kali Linux

### One-line installation

```bash
curl -fsSL https://raw.githubusercontent.com/mouhammad-coder/BurpOllama/main/install.sh | bash
```

### Manual installation

```bash
git clone https://github.com/mouhammad-coder/BurpOllama.git
cd BurpOllama
bash setup.sh
```

Setup creates `.env`, installs the Python environment, starts the backend, and
installs the `burpollama` launcher under `~/.local/bin`.

In a second terminal:

```bash
burpollama status
burpollama scan https://your-authorized-target.example
```

If `~/.local/bin` is not in your shell path:

```bash
python3 cli.py scan https://your-authorized-target.example
```

---

## AI Setup

AI is optional. Scanning and raw findings continue to work with no provider.

### Option A — Local Ollama (Private, No API Key)

BurpOllama never downloads an Ollama model automatically. Install and enable it
only when you choose:

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
```

Then enable Ollama in **Dashboard → Settings → AI Configuration**.

### Option B — Free Gemini API

1. Get a free key at [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Enter the key in **Dashboard → Settings → AI Configuration**.
3. Check Google AI Studio for the current free-tier limits.

OpenAI, Anthropic, and compatible providers can be configured on the same page.

---

## Architecture

```text
Target URL
    ↓
CLI authorization confirmation / Dashboard wizard
    ↓
Adaptive Pre-Scan Analysis
    ↓
Phase 1: Reconnaissance
(subfinder, httpx, katana, gau, JS extraction)
    ↓
Live WebSocket event stream
(phases, URLs, responses, findings, throttling)
    ↓
Phase 2: Hunt
(39 vulnerability classes, OOB confirmation)
    ↓
Phase 3: AI Triage
(3-tier: auto → batch → full CoT)
    ↓
Phase 4: Exploit Chain Builder + CVSS++ Scoring
    ↓
Phase 5: Zero FP Gate
(12-point proof check)
    ↓
Phase 6: Report
(HackerOne, Bugcrowd, Markdown, JSON, CSV, SARIF)
```

Burp Suite traffic can also be sent to the local analyzer through
`BurpOllama.py`, while all scan state, findings, reports, and configuration
remain controlled by the local FastAPI backend.

---

## Offline Verification

The repository includes a comprehensive test suite that blocks external
network and DNS access and uses only local mock data:

```bash
python tests/offline_test_suite.py
python tests/e2e_pipeline_test.py
python -m pytest -q -p no:cacheprovider -o python_files=*_tests.py
```

The E2E test starts a local mock target, runs real recon and hunt phases, and
verifies URL discovery, security-header detection, sensitive-path detection,
and clean shutdown without network access.

## Playbook and Coverage Brain

BurpOllama now generates a deterministic analyst playbook for each scan:

- `GET /scan/{scan_id}/playbook` returns ranked OWASP WSTG/API/bug-bounty
  test classes, gaps, and next-best manual validation steps.
- `GET /scan/{scan_id}/auth-coverage` shows whether authenticated and
  dual-session authorization testing is actually ready, which sensitive
  endpoint templates were discovered, and what still needs session setup.
- `GET /intelligence/program/playbook?slug=<h1-slug>` creates an advisory
  pre-scan playbook from public program scope.
- `burpollama playbook --recon-json recon.json --findings-json findings.json`
  builds the same playbook offline from exported artifacts.
- `burpollama auth-coverage --recon-json recon.json --sessions-json sessions.json`
  performs the same secret-safe auth readiness analysis offline.

This helps distinguish “no findings found” from “high-risk areas were not
covered yet,” which is critical for real bounty work.

---

## Security and Authorization

- Scan only assets you own or have written permission to test.
- Keep `.env`, API keys, authentication cookies, and exported evidence private.
- Respect program scope, request limits, and prohibited-testing rules.
- Review candidate findings manually before submitting a bounty report.

### Fresh Scope Hunter

The Autopilot page includes a daily first-mover monitor for newly observed
public bounty scope additions. Its first successful fetch creates a baseline;
only later additions are queued. Public feed data is advisory, so automatic
scans require two independent gates:

1. Save an explicit program authorization rule in Fresh Scope Hunter.
2. Add the same exact domains to BurpOllama ScopePolicy.

Automatic launch is off by default. Active testing is never enabled by the
monitor itself and continues to follow the selected scan mode. An optional
BBRadar-compatible JSON endpoint can be set with `BBRADAR_FEED_URL`. Chaos DNS
enrichment for authorized wildcard additions requires the `chaos` client and
`PDCP_API_KEY`; missing either does not interrupt monitoring.

---

## Passive Burp Suite Integration

Install Jython in Burp Suite, then load `BurpOllama.py` as a Python extension.
Every request you browse passes through BurpOllama passive analysis automatically.
WebSocket frames are also captured and analyzed.

---

## Requirements

- Kali Linux (recommended) or Ubuntu 22+
- Python 3.10+
- 8 GB RAM minimum, 16 GB recommended
- Optional: Go for recon tools and Ollama for local AI

---

## Legal Notice

Use BurpOllama only against targets you own or have explicit written permission
to test. Unauthorized testing is illegal. Always read and follow the bug bounty
program policy before scanning.

---

## File Structure

Core modules include:

- `cli.py` — Primary Rich terminal interface and WebSocket log viewer
- `hunt_engine.py` — 39 vulnerability classes and live request events
- `main.py` — FastAPI backend, scan orchestration, and WebSocket stream
- `zero_fp_gate.py` — 12-point proof validation
- `impact_scoring_engine.py` — Official CVSS 4.0 and business-impact scoring
- `exploit_chain_engine.py` — Multi-step attack path builder
- `adaptive_scan.py` — Intelligent scan depth classification
- `triage_gate.py` — 3-tier AI triage with learning engine
- `attack_graph.py` — Directed exploit chain graph
- `idor_proof_engine.py` — Dual-session IDOR confirmation
- `oob_engine.py` — interactsh OOB confirmation engine
