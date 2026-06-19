#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  BurpOllama v3 — Full Setup Script for Kali Linux
#  Installs: Python backend, Gemini client, recon tools (subfinder, httpx,
#            katana, nuclei, gau, wafw00f), Jython for Burp Suite
#  Only use against targets you own or have written authorization to test.
# ─────────────────────────────────────────────────────────────────────────────
set -e

CYAN="\033[1;36m"; GREEN="\033[1;32m"; RED="\033[1;31m"
YELLOW="\033[1;33m"; RESET="\033[0m"; BOLD="\033[1m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$SCRIPT_DIR}"
JYTHON_JAR="jython-standalone-2.7.4.jar"
JYTHON_URL="https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar"
GO_VERSION="1.22.3"

step()  { echo -e "\n${CYAN}[*]${RESET} ${BOLD}$1${RESET}"; }
ok()    { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
fail()  { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

echo -e "${CYAN}"
echo "  ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ██╗     ██╗      █████╗ "
echo "  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗██║     ██║     ██╔══██╗"
echo "  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██║     ██║     ███████║"
echo "  ██╔══██╗██║   ██║██╔══██╗██╔═══╝ ██║   ██║██║     ██║     ██╔══██║"
echo "  ██████╔╝╚██████╔╝██║  ██║██║     ╚██████╔╝███████╗███████╗██║  ██║"
echo "  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝"
echo -e "  ${YELLOW}v3 — Gemini-Powered · Recon to Report · Zero Cost${RESET}\n"

# ─── 0. Root check ────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] && warn "Running as root — tools will install system-wide."

# ─── 1. System packages ───────────────────────────────────────────────────────
step "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    curl wget git unzip tar rsync \
    default-jdk-headless \
    dnsutils net-tools lsof \
    wafw00f \
    2>/dev/null || warn "Some apt packages failed — continuing"
ok "System packages done"

# ─── 2. Go (required for ProjectDiscovery tools) ──────────────────────────────
step "Checking Go installation"
if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
else
    warn "Go not found — installing Go $GO_VERSION"
    ARCH=$(dpkg --print-architecture)
    [[ "$ARCH" == "amd64" ]] && GOARCH="amd64" || GOARCH="arm64"
    wget -q --show-progress -O /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    ok "Go $GO_VERSION installed"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ─── 3. ProjectDiscovery recon tools ─────────────────────────────────────────
step "Installing ProjectDiscovery tools (subfinder, httpx, katana, nuclei)"

install_pd_tool() {
    local name=$1
    local pkg=$2
    if command -v "$name" &>/dev/null; then
        ok "$name already installed: $(which $name)"
    else
        echo -e "  ${CYAN}→${RESET} Installing $name..."
        go install "$pkg@latest" 2>/dev/null && ok "$name installed" || warn "$name install failed — will use fallback"
    fi
}

install_pd_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_pd_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx"
install_pd_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana"
install_pd_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# gau (Get All URLs — Wayback Machine + OTX + URLScan)
if ! command -v gau &>/dev/null; then
    echo -e "  ${CYAN}→${RESET} Installing gau..."
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && ok "gau installed" || warn "gau install failed"
else
    ok "gau already installed"
fi

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    step "Updating Nuclei templates"
    nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated" || warn "Nuclei template update failed"
fi

# ─── 4. Project directory ─────────────────────────────────────────────────────
step "Setting up BurpOllama directory at $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"/jython

# Copy source files only when installing into a different directory.
if [[ "$(readlink -f "$SCRIPT_DIR")" != "$(readlink -f "$INSTALL_DIR")" ]]; then
    rsync -a \
        --exclude ".git" \
        --exclude ".venv" \
        --exclude "__pycache__" \
        --exclude "*.pyc" \
        "$SCRIPT_DIR/" "$INSTALL_DIR/"
    ok "Repository copied to $INSTALL_DIR"
else
    ok "Using repository in place: $INSTALL_DIR"
fi

# ─── 5. Python virtual environment ───────────────────────────────────────────
step "Creating Python virtual environment"
python3 -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"
pip install --upgrade pip -q
pip install -r "$INSTALL_DIR/requirements.txt" -q
ok "Python venv ready at $INSTALL_DIR/.venv"

# ─── 6. Jython JAR for Burp Suite ────────────────────────────────────────────
step "Downloading Jython standalone JAR"
JYTHON_PATH="$INSTALL_DIR/jython/$JYTHON_JAR"
if [[ -f "$JYTHON_PATH" ]]; then
    ok "Jython JAR already present: $JYTHON_PATH"
else
    wget -q --show-progress -O "$JYTHON_PATH" "$JYTHON_URL"
    ok "Jython saved: $JYTHON_PATH"
fi

# ─── 7. Gemini API key prompt ─────────────────────────────────────────────────
step "Gemini API Key Setup"
echo -e "${YELLOW}  Get your FREE key at: https://aistudio.google.com/app/apikey${RESET}"
echo -e "  Free tier: 15 req/min · 1500 req/day · gemini-2.0-flash"
echo ""
read -r -p "$(echo -e ${CYAN})[?]$(echo -e ${RESET}) Paste your Gemini API key (or press Enter to skip): " GEMINI_KEY

if [[ -n "$GEMINI_KEY" ]]; then
    # Verify the key
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://generativelanguage.googleapis.com/v1beta/models?key=$GEMINI_KEY")
    if [[ "$HTTP_CODE" == "200" ]]; then
        # Save to env file
        echo "export GEMINI_API_KEY=\"$GEMINI_KEY\"" > "$INSTALL_DIR/.env"
        echo "export GEMINI_API_KEY=\"$GEMINI_KEY\"" >> ~/.bashrc
        ok "Gemini API key verified and saved"
    else
        warn "Key returned HTTP $HTTP_CODE — saved anyway, check later"
        echo "export GEMINI_API_KEY=\"$GEMINI_KEY\"" > "$INSTALL_DIR/.env"
    fi
else
    warn "No key entered — you can set it later via the dashboard /config panel"
fi

# ─── 8. Write start / stop scripts ───────────────────────────────────────────
step "Writing start.sh and stop.sh"

cat > "$INSTALL_DIR/start.sh" << 'STARTEOF'
#!/usr/bin/env bash
CYAN="\033[1;36m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; RESET="\033[0m"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}  BurpOllama v3 — Starting${RESET}\n"

# Load env and export Ollama resource limits before starting the daemon.
[[ -f "$INSTALL_DIR/.env" ]] && set -a && source "$INSTALL_DIR/.env" && set +a
MODEL="${OLLAMA_FAST_MODEL:-${OLLAMA_MODEL:-mistral}}"
export OLLAMA_NUM_THREADS="${OLLAMA_NUM_THREADS:-8}"
export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"
[[ -n "$GEMINI_API_KEY" ]] && echo -e "${GREEN}[+]${RESET} Gemini API key loaded" \
    || echo -e "${YELLOW}[!]${RESET} No GEMINI_API_KEY found — set it in the dashboard"

if command -v ollama >/dev/null 2>&1; then
    if ! pgrep -x "ollama" >/dev/null; then
        ollama serve &>/tmp/ollama.log &
        sleep 3
    fi
    if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
        echo -e "${YELLOW}[!]${RESET} Pulling laptop-safe fast model '$MODEL'..."
        ollama pull "$MODEL"
    fi
    echo -e "${GREEN}[+]${RESET} Ollama: 1 loaded model, ${OLLAMA_NUM_THREADS} threads"
    echo -e "${YELLOW}[i]${RESET} Reasoning model downloads/loads only when needed"
fi

# Port check
if lsof -i:8888 -t &>/dev/null; then
    echo -e "${RED}[!]${RESET} Port 8888 in use. Kill it: kill \$(lsof -ti:8888)"
    exit 1
fi

# Add Go binaries to PATH
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Check recon tools
for tool in subfinder httpx katana nuclei gau wafw00f; do
    if command -v $tool &>/dev/null; then
        echo -e "${GREEN}[+]${RESET} $tool ✓"
    else
        echo -e "${YELLOW}[!]${RESET} $tool not found (fallback will be used)"
    fi
done

echo ""
source "$INSTALL_DIR/.venv/bin/activate"
cd "$INSTALL_DIR"

echo -e "${GREEN}[+]${RESET} Backend: ${YELLOW}http://127.0.0.1:8888/${RESET}"
echo -e "${GREEN}[+]${RESET} Dashboard: ${YELLOW}http://127.0.0.1:8888/ui${RESET}"
echo -e "${GREEN}[+]${RESET} Local domain style: ${YELLOW}http://burpollama.localhost:8888/ui${RESET}"
echo -e "${YELLOW}    Health    : http://127.0.0.1:8888/health${RESET}"
echo -e "${YELLOW}    Export    : http://127.0.0.1:8888/findings/export${RESET}"
echo -e "${CYAN}    Press Ctrl+C to stop${RESET}\n"
python3 main.py
STARTEOF

cat > "$INSTALL_DIR/stop.sh" << 'STOPEOF'
#!/usr/bin/env bash
echo "[*] Stopping BurpOllama..."
pkill -f "main.py" 2>/dev/null && echo "[+] Backend stopped" || echo "[!] Not running"
STOPEOF

chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh"
ok "start.sh and stop.sh written"

# ─── 9. Verify full install ───────────────────────────────────────────────────
step "Verifying installation"
echo ""
printf "  %-20s %s\n" "Python"    "$(python3 --version 2>&1)"
printf "  %-20s %s\n" "Java"      "$(java -version 2>&1 | head -1)"
printf "  %-20s %s\n" "Go"        "$(go version 2>/dev/null | head -1 || echo 'not found')"
printf "  %-20s %s\n" "subfinder" "$(command -v subfinder &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "httpx"     "$(command -v httpx &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "katana"    "$(command -v katana &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "nuclei"    "$(command -v nuclei &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "gau"       "$(command -v gau &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "wafw00f"   "$(command -v wafw00f &>/dev/null && echo '✓' || echo '✗ fallback')"
printf "  %-20s %s\n" "Jython JAR" "$JYTHON_PATH"
echo ""

# ─── 10. Final instructions ───────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}  SETUP COMPLETE${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BOLD}STEP 1 — Start the backend:${RESET}"
echo -e "  ${YELLOW}cd $INSTALL_DIR && bash start.sh${RESET}"
echo ""
echo -e "${BOLD}STEP 2 — Open dashboard:${RESET}"
echo -e "  ${YELLOW}firefox http://127.0.0.1:8888/ui${RESET}"
echo ""
echo -e "${BOLD}STEP 3 — Paste Gemini API key in the dashboard CONFIG panel${RESET}"
echo -e "  Get free key: ${YELLOW}https://aistudio.google.com/app/apikey${RESET}"
echo ""
echo -e "${BOLD}STEP 4 — Enter target and click START AUTOMATED SCAN${RESET}"
echo -e "  Pipeline: Recon → Hunt → Triage (7Q Gate) → Analysis → Report"
echo ""
echo -e "${BOLD}STEP 5 — Optional: Load Burp Extension for passive live analysis${RESET}"
echo -e "  a) Burp → Extender → Options → Jython JAR:"
echo -e "     ${YELLOW}$JYTHON_PATH${RESET}"
echo -e "  b) Extender → Extensions → Add → Python:"
echo -e "     ${YELLOW}$INSTALL_DIR/BurpOllama.py${RESET}"
echo ""
echo -e "${BOLD}STEP 6 — When scan finishes, click VIEW FULL REPORT${RESET}"
echo -e "  Or download: ${YELLOW}http://localhost:8888/scan/<id>/report/download${RESET}"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${RED}  Only test targets you own or have written authorization for.${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
