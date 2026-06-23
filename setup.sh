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
echo "You will choose and configure an AI provider inside the dashboard."
echo "Scans work without AI. Ollama remains disabled until you enable it."

chmod +x "$SCRIPT_DIR/setup.sh" \
    "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/update.sh" "$SCRIPT_DIR/burpollama" \
    "$SCRIPT_DIR/cli.py" 2>/dev/null || true
mkdir -p "$HOME/.local/bin"
ln -sf "$SCRIPT_DIR/burpollama" "$HOME/.local/bin/burpollama"
echo -e "${GREEN}[+]${RESET} CLI installed at $HOME/.local/bin/burpollama"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║         BURPOLLAMA IS READY               ║${RESET}"
echo -e "${GREEN}╠═══════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}║  Dashboard: http://127.0.0.1:8888/ui      ║${RESET}"
echo -e "${GREEN}║  Press Ctrl+C to stop                     ║${RESET}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${RESET}"
echo ""

exec bash "$SCRIPT_DIR/start.sh"
