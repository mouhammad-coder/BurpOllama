#!/usr/bin/env bash
# Update BurpOllama to latest version
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Backing up configuration..."
cp .env .env.backup 2>/dev/null || true

echo "[*] Pulling latest changes..."
git pull

echo "[*] Updating Python packages..."
source .venv/bin/activate
pip install -r requirements.txt -q

echo "[*] Restoring configuration..."
cp .env.backup .env 2>/dev/null || true

echo "[+] Update complete. Run: bash start.sh"
