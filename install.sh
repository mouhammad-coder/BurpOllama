#!/usr/bin/env bash
# BurpOllama - One line installer
# Run: curl -fsSL https://raw.githubusercontent.com/mouhammad-coder/BurpOllama/main/install.sh | bash

set -e
INSTALL_DIR="$HOME/tools/BurpOllama"

echo "Installing BurpOllama..."

# Install system dependencies
sudo apt-get install -y python3 python3-venv python3-pip git curl wget \
    default-jdk-headless dnsutils lsof wafw00f 2>/dev/null

# Clone or update repo
if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    git clone https://github.com/mouhammad-coder/BurpOllama.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Run setup
bash setup.sh

echo ""
echo "Installation complete. BurpOllama is starting..."
