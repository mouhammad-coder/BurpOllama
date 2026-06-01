#!/bin/bash
# ================================================================
# BurpOllama - One-Click Setup for Kali Linux
# Local AI-Powered Bug Hunting Pipeline
# ================================================================
# This script installs everything needed to run the BurpOllama
# bug hunting pipeline on Kali Linux.
#
# What it installs:
#   1. Python dependencies (FastAPI, Uvicorn, httpx)
#   2. Ollama (local AI model runner)
#   3. DeepSeek-Coder or Llama 3.1 model for security analysis
#   4. Jython (for Burp Suite extension)
#   5. Configures Burp Suite extension
#   6. Starts all services
#
# Usage:
#   chmod +x setup_kali.sh
#   ./setup_kali.sh                    # Full setup (recommended)
#   ./setup_kali.sh --minimal          # Minimal setup (no model download)
#   ./setup_kali.sh --model deepseek   # Use DeepSeek-Coder (default)
#   ./setup_kali.sh --model llama      # Use Llama 3.1
# ================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
MODEL_CHOICE="deepseek"
MINIMAL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal) MINIMAL=true; shift ;;
        --model)
            shift
            if [[ $1 == "deepseek" ]]; then MODEL_CHOICE="deepseek"
            elif [[ $1 == "llama" ]]; then MODEL_CHOICE="llama"
            else echo "Unknown model: $1. Using deepseek."; MODEL_CHOICE="deepseek"
            fi
            shift ;;
        --help)
            echo "Usage: $0 [--minimal] [--model deepseek|llama]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ================================================================
# BANNER
# ================================================================
print_banner() {
    echo -e "${CYAN}"
    echo '  ╔══════════════════════════════════════════════════╗'
    echo '  ║              BURPOLLAMA SETUP                     ║'
    echo '  ║     Local AI Bug Hunting Pipeline for Kali        ║'
    echo '  ╚══════════════════════════════════════════════════╝'
    echo -e "${NC}"
    echo -e "${YELLOW}  Model: ${MODEL_CHOICE} | Minimal: ${MINIMAL}${NC}"
    echo
}

# ================================================================
# HELPER FUNCTIONS
# ================================================================
print_step() { echo -e "${GREEN}[+]${NC} ${BOLD}$1${NC}"; }
print_info() { echo -e "${CYAN}[*]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_section() {
    echo
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

command_exists() { command -v "$1" &>/dev/null; }

check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ Done${NC}"
    else
        echo -e "${RED}  ✗ Failed${NC}"
        return 1
    fi
}

# ================================================================
# MAIN SETUP
# ================================================================
main() {
    print_banner

    # Check if running as root (not required, but good for package installs)
    if [[ $EUID -eq 0 ]]; then
        print_warn "Running as root. This is fine for package installation."
    fi

    # ================================================================
    # STEP 1: System Dependencies
    # ================================================================
    print_section "Step 1: System Dependencies"

    print_step "Updating package lists..."
    sudo apt-get update -qq 2>/dev/null || true

    print_step "Installing system packages (Python3, pip, Java, curl)..."
    sudo apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        default-jre \
        default-jdk \
        curl \
        wget \
        git \
        netcat-openbsd \
        2>&1 | tail -1
    check_success

    # ================================================================
    # STEP 2: Python Virtual Environment & Dependencies
    # ================================================================
    print_section "Step 2: Python Dependencies"

    print_step "Creating Python virtual environment..."
    cd "$SCRIPT_DIR"
    python3 -m venv venv 2>/dev/null || {
        print_warn "venv module not available, installing..."
        sudo apt-get install -y -qq python3-venv
        python3 -m venv venv
    }
    check_success

    print_step "Installing Python packages..."
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    check_success

    # Install httpx explicitly
    pip install httpx -q 2>/dev/null && print_info "  httpx installed"

    # ================================================================
    # STEP 3: Ollama Installation
    # ================================================================
    print_section "Step 3: Ollama (Local AI)"

    if command_exists ollama; then
        print_step "Ollama already installed"
        ollama --version
    else
        print_step "Installing Ollama..."
        print_info "  Downloading from https://ollama.com/install.sh"
        curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -3
        check_success

        print_step "Waiting for Ollama to start..."
        sleep 3

        # Check if Ollama service is running
        if systemctl is-active --quiet ollama 2>/dev/null; then
            print_info "  Ollama service is active"
        else
            print_warn "  Starting Ollama service..."
            sudo systemctl start ollama 2>/dev/null || {
                print_info "  Starting Ollama in background..."
                nohup ollama serve > /tmp/ollama.log 2>&1 &
                sleep 3
            }
        fi
    fi

    # ================================================================
    # STEP 4: Download Model
    # ================================================================
    print_section "Step 4: Download AI Model"

    if [ "$MINIMAL" = true ]; then
        print_warn "Minimal mode - skipping model download"
        print_info "  Run later: ollama pull deepseek-coder:6.7b"
        print_info "  Or:        ollama pull llama3.1:8b"
    else
        # Wait for Ollama to be ready
        print_step "Waiting for Ollama API..."
        for i in $(seq 1 30); do
            if curl -s http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
                print_info "  Ollama API ready"
                break
            fi
            if [ $i -eq 30 ]; then
                print_warn "  Ollama not responding. Starting it manually..."
                nohup ollama serve > /tmp/ollama.log 2>&1 &
                sleep 5
            fi
            sleep 1
        done

        if [ "$MODEL_CHOICE" = "deepseek" ]; then
            MODEL_NAME="deepseek-coder:6.7b"
            print_step "Downloading DeepSeek-Coder 6.7B (~4GB)..."
        else
            MODEL_NAME="llama3.1:8b"
            print_step "Downloading Llama 3.1 8B (~4.7GB)..."
        fi

        print_info "  This is a large download and may take 10-30 minutes"
        print_info "  Model: ${MODEL_NAME}"
        print_info "  Starting download..."

        ollama pull "$MODEL_NAME" 2>&1 | tail -5

        if [ $? -eq 0 ]; then
            print_step "Model downloaded successfully!"
            # Verify
            curl -s http://127.0.0.1:11434/api/tags | python3 -c "
import json, sys
data = json.load(sys.stdin)
models = [m['name'] for m in data.get('models', [])]
print(f'  Available models: {models}')
" 2>/dev/null || print_info "  Model ready"
        else
            print_warn "Download may have failed. Run manually: ollama pull ${MODEL_NAME}"
        fi
    fi

    # ================================================================
    # STEP 5: Jython for Burp Extension
    # ================================================================
    print_section "Step 5: Jython (for Burp Extension)"

    JYTHON_VERSION="2.7.3"
    JYTHON_JAR="$SCRIPT_DIR/burp_extension/jython-standalone-${JYTHON_VERSION}.jar"

    if [ -f "$JYTHON_JAR" ]; then
        print_step "Jython already downloaded: $JYTHON_JAR"
    else
        print_step "Downloading Jython standalone ${JYTHON_VERSION}..."
        cd "$SCRIPT_DIR/burp_extension"
        curl -sL "https://repo1.maven.org/maven2/org/python/jython-standalone/${JYTHON_VERSION}/jython-standalone-${JYTHON_VERSION}.jar" \
            -o "jython-standalone-${JYTHON_VERSION}.jar" \
            --progress-bar 2>&1 | tail -1
        check_success
    fi

    # ================================================================
    # STEP 6: Data Directory
    # ================================================================
    print_section "Step 6: Data Directory"

    mkdir -p "$SCRIPT_DIR/data"
    print_step "Data directory: $SCRIPT_DIR/data"
    check_success

    # ================================================================
    # STEP 7: Make Scripts Executable
    # ================================================================
    print_section "Step 7: Making Scripts Executable"

    chmod +x "$SCRIPT_DIR/start.sh" 2>/dev/null || true
    chmod +x "$SCRIPT_DIR/burp_ollama.py" 2>/dev/null || true
    print_step "Scripts are executable"

    # ================================================================
    # DONE
    # ================================================================
    echo
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║             SETUP COMPLETE!                       ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Next Steps:${NC}"
    echo
    echo -e "${BOLD}  1. Start the analyzer server:${NC}"
    echo -e "     ${YELLOW}    cd ${SCRIPT_DIR} && ./start.sh${NC}"
    echo
    echo -e "${BOLD}  2. Open the dashboard:${NC}"
    echo -e "     ${YELLOW}    http://127.0.0.1:9999${NC}"
    echo
    echo -e "${BOLD}  3. Configure Burp Suite:${NC}"
    echo -e "     ${YELLOW}    Burp → Extender → Extensions → Add${NC}"
    echo -e "     ${YELLOW}    Type: Python, File: burp_extension/burp_ollama_bridge.py${NC}"
    echo -e "     ${YELLOW}    Leave Jython JAR at: burp_extension/jython-standalone-2.7.3.jar${NC}"
    echo
    echo -e "${BOLD}  4. Test without Burp:${NC}"
    echo -e "     ${YELLOW}    source venv/bin/activate${NC}"
    echo -e "     ${YELLOW}    python3 burp_ollama.py check${NC}"
    echo -e "     ${YELLOW}    python3 burp_ollama.py send-url https://target.com/api/users?id=1${NC}"
    echo
    echo -e "${BOLD}  5. Kali terminal aliases (optional):${NC}"
    echo -e "     ${YELLOW}    echo 'alias burpollama=\"cd ${SCRIPT_DIR} && ./start.sh\"' >> ~/.bashrc${NC}"
    echo -e "     ${YELLOW}    source ~/.bashrc${NC}"
    echo
    echo -e "${BOLD}  6. Test the full pipeline:${NC}"
    echo -e "     ${YELLOW}    python3 burp_ollama.py raw POST https://example.com/api/login \\\\${NC}"
    echo -e "     ${YELLOW}      -H \"Content-Type: application/json\" \\\\${NC}"
    echo -e "     ${YELLOW}      -b '{\"username\":\"admin\",\"password\":\"admin123\"}'${NC}"
    echo
    echo -e "${BOLD}  7. Batch analyze files:${NC}"
    echo -e "     ${YELLOW}    python3 burp_ollama.py batch /path/to/target/dir --ext .js,.json,.env${NC}"
    echo
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Happy Bug Hunting! 🐛${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
}

# Run main
main
