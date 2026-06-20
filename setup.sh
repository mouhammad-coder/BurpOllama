#!/usr/bin/env bash
# BurpOllama v3 - Automatic Kali/Linux setup
set -e

CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}[*]${RESET} Installing BurpOllama system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip git curl wget \
    default-jdk-headless dnsutils lsof wafw00f 2>/dev/null || \
    echo -e "${YELLOW}[!]${RESET} Some optional system tools could not be installed."

echo -e "${CYAN}[*]${RESET} Creating Python virtual environment..."
if [[ ! -d "$SCRIPT_DIR/.venv" ]]; then
    python3 -m venv "$SCRIPT_DIR/.venv"
fi
source "$SCRIPT_DIR/.venv/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo -e "${CYAN}[*]${RESET} Installing optional Semgrep support..."
pip install semgrep --break-system-packages 2>/dev/null || pip install semgrep || \
    echo -e "${YELLOW}[!]${RESET} Semgrep installation failed; setup will continue with regex analysis."

if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    echo -e "${GREEN}[+]${RESET} Created .env from .env.example."
else
    echo -e "${GREEN}[+]${RESET} Existing .env preserved."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI PROVIDER SETUP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Choose your AI option:"
echo "  1) Install Ollama (FREE - runs locally, no internet needed)"
echo "  2) Use Gemini free API (FREE - needs Google account)"
echo "  3) Skip AI setup (configure later in dashboard)"
echo ""
read -r -p "Choice [1/2/3]: " AI_CHOICE

if [[ "$AI_CHOICE" == "1" ]]; then
    echo "[*] Installing Ollama..."
    curl -fsSL https://ollama.ai/install.sh | sh
    echo "[*] Pulling mistral model (this takes 5-10 minutes)..."
    ollama pull mistral &
    OLLAMA_PID=$!
    echo "[+] Ollama installing in background (PID: $OLLAMA_PID)"
    echo "    Check progress: ollama list"
    echo "OLLAMA_ENABLED=1" >> .env
    echo "OLLAMA_MODEL=mistral" >> .env
elif [[ "$AI_CHOICE" == "2" ]]; then
    echo ""
    echo "  Get your FREE Gemini key at:"
    echo "  https://aistudio.google.com/app/apikey"
    echo ""
    read -r -p "Paste your Gemini API key (or Enter to skip): " GEMINI_KEY
    if [[ -n "$GEMINI_KEY" ]]; then
        echo "GEMINI_API_KEY=$GEMINI_KEY" >> .env
        echo "CLOUD_AI_ENABLED=1" >> .env
        echo "[+] Gemini key saved"
    fi
else
    echo "[*] Skipping AI setup. Configure later in the dashboard."
fi

chmod +x "$SCRIPT_DIR/setup.sh" "$SCRIPT_DIR/start.sh" \
    "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/update.sh" 2>/dev/null || true

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║         BURPOLLAMA IS READY               ║${RESET}"
echo -e "${GREEN}╠═══════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}║  Dashboard: http://127.0.0.1:8888/ui      ║${RESET}"
echo -e "${GREEN}║  Press Ctrl+C to stop                     ║${RESET}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${RESET}"
echo ""

exec bash "$SCRIPT_DIR/start.sh"
