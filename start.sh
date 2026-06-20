#!/usr/bin/env bash
# BurpOllama - Foolproof launcher
set -e

CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d "$SCRIPT_DIR/.venv" ]]; then
    echo -e "${CYAN}[*]${RESET} Creating Python virtual environment..."
    python3 -m venv "$SCRIPT_DIR/.venv"
    source "$SCRIPT_DIR/.venv/bin/activate"
    python -m pip install --upgrade pip
    python -m pip install -r "$SCRIPT_DIR/requirements.txt"
    python -m pip install semgrep --break-system-packages 2>/dev/null || python -m pip install semgrep || \
        echo -e "${YELLOW}[!]${RESET} Semgrep could not be installed; BurpOllama will use regex analysis."
else
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

PID=$(lsof -ti:8888 2>/dev/null || true)
if [[ -n "$PID" ]]; then
    echo -e "${YELLOW}[!]${RESET} Port 8888 is busy. Stopping the old process..."
    kill -9 $PID 2>/dev/null || true
    sleep 1
fi

OLLAMA_RUNNING=false
if [[ "${OLLAMA_ENABLED:-1}" != "0" ]] && curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    OLLAMA_RUNNING=true
fi

if [[ "$OLLAMA_RUNNING" == "true" ]]; then
    echo -e "${GREEN}[+]${RESET} Local Ollama is available."
elif [[ -n "${GEMINI_API_KEY:-}" || -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "${GREEN}[+]${RESET} Cloud AI provider configured."
else
    echo -e "${YELLOW}No AI provider configured. Scans will run with manual review only.${RESET}"
fi

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║          BURPOLLAMA STARTING              ║${RESET}"
echo -e "${CYAN}╠═══════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║  Dashboard: http://127.0.0.1:8888/ui      ║${RESET}"
echo -e "${CYAN}║  API:       http://127.0.0.1:8888         ║${RESET}"
echo -e "${CYAN}║  Health:    http://127.0.0.1:8888/health  ║${RESET}"
echo -e "${CYAN}║  Ready:     http://127.0.0.1:8888/ready   ║${RESET}"
echo -e "${CYAN}║  Press Ctrl+C to stop                     ║${RESET}"
echo -e "${CYAN}╚═══════════════════════════════════════════╝${RESET}"
echo ""

(sleep 2 && xdg-open http://127.0.0.1:8888/ui >/dev/null 2>&1) &
exec uvicorn main:app --host 127.0.0.1 --port 8888 --reload
