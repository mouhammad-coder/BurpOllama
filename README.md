# BurpOllama

<p align="center">
  <img src="https://img.shields.io/badge/Python-89.6%25-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-Private-red?style=for-the-badge" alt="Private License">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-black?style=for-the-badge&logo=linux" alt="Kali Linux">
  <img src="https://img.shields.io/badge/AI-Local%20%2B%20Cloud-green?style=for-the-badge" alt="Local and Cloud AI">
  <img src="https://img.shields.io/badge/Classes-39%20Vuln%20Classes-orange?style=for-the-badge" alt="39 Vulnerability Classes">
</p>

<p align="center">
<b>Local autonomous bug bounty platform with AI triage, 39 vulnerability classes,
Zero FP mode, exploit chain builder, and bounty-ready report export.</b>
</p>

---

## What It Does

BurpOllama is a local web-based security platform that runs on your machine.
You open the dashboard, enter an authorized target, and it:

- Discovers attack surface automatically
- Tests 39 vulnerability classes
- Confirms findings with actual proof (not just detection)
- Scores everything with CVSS++ business-aware impact scoring
- Builds exploit chains connecting related vulnerabilities
- Exports HackerOne and Bugcrowd ready reports

**No cloud dependency. No subscription. Runs on your laptop.**

> Use BurpOllama only on systems you own or have explicit written authorization to test.

---

## Dashboard

The dashboard lives at `http://127.0.0.1:8888/ui`

Guided step-by-step wizard — no command line knowledge needed.

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

```bash
git clone https://github.com/mouhammad-coder/BurpOllama.git
cd BurpOllama
cp .env.example .env
bash setup.sh
```

Open: [http://127.0.0.1:8888/ui](http://127.0.0.1:8888/ui)

The setup script starts the dashboard automatically and installs the
`burpollama` launcher under `~/.local/bin`.

---

## AI Setup

### Option A — Free Gemini API (Recommended for Beginners)

1. Get a free key at [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Enter the key in **Dashboard → Settings → AI Configuration**.
3. The free tier currently offers limited requests; check Google AI Studio for current quotas.

### Option B — Local Ollama (No API Key Needed)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
```

Configure it in **Dashboard → Settings → AI Configuration**.

---

## Architecture

```text
Target URL
    ↓
Guided Wizard (scope, mode, sessions)
    ↓
Adaptive Pre-Scan Analysis
    ↓
Phase 1: Reconnaissance
(subfinder, httpx, katana, gau, JS extraction)
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
(HackerOne, Bugcrowd, Markdown, JSON)
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
```

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

54 Python modules, including:

- `hunt_engine.py` — 38 vulnerability classes
- `main.py` — FastAPI backend with 50+ endpoints
- `zero_fp_gate.py` — 12-point proof validation
- `impact_scoring_engine.py` — CVSS++ scoring
- `exploit_chain_engine.py` — Multi-step attack path builder
- `adaptive_scan.py` — Intelligent scan depth classification
- `triage_gate.py` — 3-tier AI triage with learning engine
- `attack_graph.py` — Directed exploit chain graph
- `idor_proof_engine.py` — Dual-session IDOR confirmation
- `oob_engine.py` — interactsh OOB confirmation engine
