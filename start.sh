#!/bin/bash
# ================================================================
# BurpOllama - Start Script
# Launches the analyzer server + optional Ollama check
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}"
echo '  ╔══════════════════════════════════════════════════╗'
echo '  ║            BURPOLLAMA ANALYZER SERVER             ║'
echo '  ║          Local AI Bug Hunting Pipeline            ║'
echo '  ╚══════════════════════════════════════════════════╝'
echo -e "${NC}"

# Check Python virtual environment
if [ -d "venv" ]; then
    echo -e "${GREEN}[+]${NC} Using virtual environment"
    source venv/bin/activate
else
    echo -e "${YELLOW}[!]${NC} No virtual environment found. Using system Python."
fi

# Check if required packages are installed
python3 -c "import fastapi" 2>/dev/null || {
    echo -e "${YELLOW}[!]${NC} Installing Python dependencies..."
    pip install -r requirements.txt -q
    pip install httpx -q 2>/dev/null || true
}

# Check if Ollama is running
echo -e "${GREEN}[+]${NC} Checking Ollama connection..."
python3 -c "
import urllib.request, json
try:
    r = urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=3)
    data = json.loads(r.read())
    models = [m['name'] for m in data.get('models', [])]
    print('  ✓ Ollama connected - Models:', ', '.join(models[:3]) if models else 'none')
except:
    print('  ⚠ Ollama not detected. AI analysis will be disabled.')
    print('  Run: ollama serve')
" 2>/dev/null || echo -e "  ${YELLOW}⚠ Could not check Ollama${NC}"

# Create data directory
mkdir -p "$SCRIPT_DIR/data"

# Kill any existing instance on port 9999
lsof -ti:9999 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# Print info
echo
echo -e "${GREEN}[+]${NC} Starting analyzer server..."
echo -e "${GREEN}[+]${NC} Dashboard:  ${BOLD}http://127.0.0.1:9999${NC}"
echo -e "${GREEN}[+]${NC} Burp API:   ${BOLD}http://127.0.0.1:9999/api/traffic${NC}"
echo -e "${GREEN}[+]${NC} WebSocket:  ${BOLD}ws://127.0.0.1:9999/ws${NC}"
echo

# Start the server
python3 analyzer/server.py

# If the script exits, clean up
echo -e "${YELLOW}[!]${NC} Server stopped."
