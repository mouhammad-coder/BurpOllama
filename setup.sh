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
mkdir -p "$HOME/.local/bin"

echo -e "${CYAN}[*]${RESET} Installing optional Semgrep in an isolated environment..."
SEMGREP_VENV="$SCRIPT_DIR/.tools/semgrep"
if python3 -m venv "$SEMGREP_VENV" 2>/dev/null; then
    "$SEMGREP_VENV/bin/python" -m pip install --upgrade pip -q
    "$SEMGREP_VENV/bin/python" -m pip install semgrep -q || \
        echo -e "${YELLOW}[!]${RESET} Semgrep installation failed; regex analysis remains available."
    if [[ -x "$SEMGREP_VENV/bin/semgrep" ]]; then
        ln -sf "$SEMGREP_VENV/bin/semgrep" "$HOME/.local/bin/semgrep"
    fi
else
    echo -e "${YELLOW}[!]${RESET} Could not create the optional Semgrep environment."
fi

if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    echo -e "${GREEN}[+]${RESET} Created .env from .env.example."
else
    echo -e "${GREEN}[+]${RESET} Existing .env preserved."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  OPTIONAL AI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Scans work without AI and use manual-review status when needed."
echo "Configure a provider later in .env or with the optional dashboard."

chmod +x "$SCRIPT_DIR/setup.sh" \
    "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/update.sh" "$SCRIPT_DIR/burpollama" \
    "$SCRIPT_DIR/cli.py" 2>/dev/null || true
ln -sf "$SCRIPT_DIR/burpollama" "$HOME/.local/bin/burpollama"
echo -e "${GREEN}[+]${RESET} CLI installed at $HOME/.local/bin/burpollama"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║              BURPOLLAMA CLI IS READY               ║${RESET}"
echo -e "${GREEN}╠════════════════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}║  burpollama doctor                                 ║${RESET}"
echo -e "${GREEN}║  burpollama status                                 ║${RESET}"
echo -e "${GREEN}║  burpollama scan <target> --mode passive           ║${RESET}"
echo -e "${GREEN}║  burpollama serve       (optional dashboard)       ║${RESET}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "Open a new terminal if ~/.local/bin was not already in PATH."
