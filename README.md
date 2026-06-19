# BurpOllama

Autonomous bug bounty and application security scanner with recon, passive Burp analysis, WAF-aware throttling, OOB verification, AI triage, attack graphing, and report generation.

Use this only against targets you own or have explicit written authorization to test.

## Kali Quick Start

```bash
git clone https://github.com/YOUR-ORG/BurpOllama.git
cd BurpOllama
cp .env.example .env
bash setup.sh
bash start.sh
```

Dashboard: `http://127.0.0.1:8888/ui`

Local domain style: `http://burpollama.localhost:8888/ui`

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

- Local Ollama: `OLLAMA_ENABLED=1`, default model `llama3.1`
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

- Replace `YOUR-ORG` in this README after creating the GitHub repository.
- Review `setup.sh` before running with sudo on a new Kali host.
- Confirm the project license before public release.
- Keep bug bounty program scope and rate limits in configuration or engagement notes.
