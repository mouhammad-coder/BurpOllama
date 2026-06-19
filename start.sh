#!/usr/bin/env bash
# BurpOllama — Quick Start
CYAN="\033[1;36m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; RESET="\033[0m"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$INSTALL_DIR/.env" ]] && set -a && source "$INSTALL_DIR/.env" && set +a
MODEL="${OLLAMA_FAST_MODEL:-${OLLAMA_MODEL:-mistral}}"
export OLLAMA_NUM_THREADS="${OLLAMA_NUM_THREADS:-8}"
export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"

echo -e "${CYAN}  BurpOllama — Starting...${RESET}\n"

# 1. Optional local LLM daemon
if command -v ollama >/dev/null 2>&1; then
    if ! pgrep -x "ollama" > /dev/null; then
        echo -e "${CYAN}[*]${RESET} Starting Ollama daemon..."
        ollama serve &>/tmp/ollama.log &
        sleep 3
        echo -e "${GREEN}[+]${RESET} Ollama daemon started"
    else
        echo -e "${GREEN}[+]${RESET} Ollama already running"
    fi

    if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
        echo -e "${YELLOW}[!]${RESET} Fast model '$MODEL' not found. Pulling now..."
        ollama pull "$MODEL"
    fi
    echo -e "${GREEN}[+]${RESET} Ollama laptop-safe mode: 1 loaded model, ${OLLAMA_NUM_THREADS} threads"
    echo -e "${YELLOW}[i]${RESET} Reasoning model loads lazily when a high-risk prompt needs it."
else
    echo -e "${YELLOW}[!]${RESET} Ollama not found; cloud AI providers or API keys will be used."
fi

# 3. Check port 8888 is free
if lsof -i:8888 -t &>/dev/null; then
    echo -e "${RED}[!]${RESET} Port 8888 already in use. Kill it first:"
    echo -e "    ${YELLOW}kill \$(lsof -ti:8888)${RESET}"
    exit 1
fi

# 4. Activate venv and start backend
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    echo -e "${YELLOW}[!]${RESET} Virtualenv not found. Creating it now..."
    python3 -m venv "$INSTALL_DIR/.venv"
    source "$INSTALL_DIR/.venv/bin/activate"
    pip install --upgrade pip
    pip install -r "$INSTALL_DIR/requirements.txt"
else
    source "$INSTALL_DIR/.venv/bin/activate"
fi
cd "$INSTALL_DIR"

echo -e "${GREEN}[+]${RESET} Backend: ${YELLOW}http://127.0.0.1:8888/${RESET}"
echo -e "${GREEN}[+]${RESET} Dashboard: ${YELLOW}http://127.0.0.1:8888/ui${RESET}"
echo -e "${GREEN}[+]${RESET} Local domain style: ${YELLOW}http://burpollama.localhost:8888/ui${RESET}"
echo -e "${YELLOW}    Health    : http://127.0.0.1:8888/health${RESET}"
echo -e "${YELLOW}    Export    : http://127.0.0.1:8888/findings/export${RESET}"
echo -e "${CYAN}    Press Ctrl+C to stop${RESET}\n"

python3 main.py
