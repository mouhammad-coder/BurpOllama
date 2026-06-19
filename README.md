# BurpOllama

Autonomous bug bounty and application security scanner with recon, passive Burp analysis, WAF-aware throttling, OOB verification, AI triage, attack graphing, and report generation.

Use this only against targets you own or have explicit written authorization to test.

## Kali Quick Start

```bash
git clone https://github.com/mouhammad-coder/BurpOllama.git
cd BurpOllama
cp .env.example .env
bash setup.sh
bash start.sh
```

Guided Start Wizard: `http://127.0.0.1:8888/ui/start`

Local domain style: `http://burpollama.localhost:8888/ui/start`

The default interface guides users through target, authorization, scope, scan mode,
AI mode, optional login sessions, final review, live progress, and results. The
original expert dashboard remains available under **Advanced Console**.

Open **Settings** in the sidebar to configure API keys, local Ollama models,
reasoning limits, storage, and callback verification. BurpOllama creates and
updates `.env` automatically, masks saved secrets, tests providers, and can
download missing `mistral` or `llama3.1:8b` models from the browser.

## Adaptive Scan Engine

BurpOllama profiles each authorized target before testing and selects a
LIGHT, BALANCED, or DEEP execution plan based on endpoint count, response
complexity, APIs, authentication, GraphQL, JavaScript usage, admin panels,
and parameter density.

- LIGHT limits discovery and runs static, low-cost checks.
- BALANCED is the default and selectively activates relevant modules.
- DEEP expands authenticated, IDOR/BOLA, business-logic, and exploit-chain analysis.

The plan controls URL budgets, request batching, concurrency, timeouts, CPU
backpressure, and AI depth. Use `POST /auto/profile-target` with an authorized
target to preview the profile and selected plan.

API health: `http://127.0.0.1:8888/health`

Metrics: `http://127.0.0.1:8888/metrics`

## Minimal Manual Install

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip curl wget git dnsutils lsof wafw00f
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Optional recon tools:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

## AI Providers

BurpOllama now routes AI calls through a provider-agnostic layer:

- Fast local Ollama model: `mistral`
- High-risk reasoning model: `llama3.1:8b`, loaded only when needed
- Laptop-safe defaults: 8 CPU threads, one loaded model, 4096/6144 context
- Memory-aware fallback: reasoning is skipped below 3.5 GB free physical RAM
- Gemini: `GEMINI_API_KEY`
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`

The router prefers low-cost available providers and fails over automatically.

## PostgreSQL / Enterprise Mode

Local mode uses SQLite under `~/.burpollama`. For PostgreSQL-backed event and audit storage:

```bash
cp .env.example .env
# edit BURPOLLAMA_DATABASE_URL
docker compose up --build
```

## Burp Extension

Install Jython in Burp Suite, then add `BurpOllama.py` as a Python extension. The extension ships passive HTTP and WebSocket traffic to the local backend at `http://localhost:8888/analyze`.

## Key Endpoints

- `POST /scan` starts a scan
- `POST /auto/profile-target` previews the adaptive target profile and scan plan
- `GET /scan/{scan_id}` returns scan state
- `GET /scan/{scan_id}/report` returns Markdown report
- `GET /scan/{scan_id}/attack-graph` returns exploit-chain graph output
- `GET /scan/{scan_id}/coverage` returns coverage intelligence
- `GET /ai/providers` returns provider health/cost state
- `GET /scheduler` returns distributed scheduler state
- `GET /storage` returns event/audit storage state
- `GET /metrics` returns Prometheus-style metrics

## Security Notes

- Do not commit `.env` or API keys.
- Reports redact common secret formats and escape target-controlled evidence.
- OOB payloads include signed nonce attribution when `BURPOLLAMA_OOB_SIGNING_KEY` is set.
- Advanced classes such as request smuggling, race conditions, business logic abuse, file upload abuse, and GraphQL authorization emit candidates unless the scanner has direct exploit proof.

## Publishing Checklist

- Review `setup.sh` before running with sudo on a new Kali host.
- Confirm the project license before public release.
- Keep bug bounty program scope and rate limits in configuration or engagement notes.
