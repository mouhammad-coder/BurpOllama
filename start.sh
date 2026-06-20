#!/usr/bin/env bash
# BurpOllama - Fast launcher
set -e

CYAN="\033[1;36m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d "$SCRIPT_DIR/.venv" ]]; then
    echo -e "${RED}[!]${RESET} Python virtual environment not found."
    echo "    Run: bash setup.sh"
    exit 1
fi

PID=$(lsof -ti:8888 2>/dev/null || true)
if [[ -n "$PID" ]]; then
    echo -e "${YELLOW}[!]${RESET} Port 8888 is busy. Stopping the old process..."
    kill -9 $PID 2>/dev/null || true
fi

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

if [[ "${OLLAMA_ENABLED:-0}" == "1" ]]; then
    OLLAMA_STATUS=$(curl -fsS --max-time 1 http://127.0.0.1:11434/api/tags 2>/dev/null || true)
    if [[ -z "$OLLAMA_STATUS" ]]; then
        echo -e "${YELLOW}[!]${RESET} Ollama is enabled but not running. Continuing without local AI."
    elif [[ "$OLLAMA_STATUS" != *"mistral"* ]]; then
        echo -e "${YELLOW}[!]${RESET} Ollama is running but mistral is not installed. Install it manually from the dashboard."
    else
        echo -e "${GREEN}[+]${RESET} Local Ollama and mistral are available."
    fi
elif [[ -n "${GEMINI_API_KEY:-}" || -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "${GREEN}[+]${RESET} Cloud AI provider configured."
else
    echo -e "${YELLOW}[!]${RESET} No AI provider configured. Scans will run with manual review only."
fi

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

# shellcheck disable=SC1091
source "$SCRIPT_DIR/.venv/bin/activate"
exec uvicorn main:app --host 127.0.0.1 --port 8888 --reload
