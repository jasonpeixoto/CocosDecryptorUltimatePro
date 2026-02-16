#!/bin/bash

# Cocos Decryptor - Automated macOS Setup Script
set -e

echo "------------------------------------------------"
echo "🚀 Starting Cocos Decryptor Environment Setup"
echo "------------------------------------------------"

# 1. Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "🔍 Homebrew not found. Installing now..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add brew to path for the current session
    if [[ "$(uname -m)" == "arm64" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        eval "$(/usr/local/bin/brew shellenv)"
    fi
else
    echo "✅ Homebrew is already installed."
fi

# 2. Install System Binaries
echo "📦 Installing system dependencies (apktool, node, prettier)..."
brew install apktool node prettier

# 3. Install Python Dependencies
echo "🐍 Installing Python packages..."
if command -v pip3 &> /dev/null; then
    pip3 install PyQt5
else
    echo "❌ pip3 not found. Please install Python 3 from python.org"
    exit 1
fi

# 4. Final Permissions Check
echo "🔐 Ensuring local scripts are executable..."
chmod +x DecryptCococas.py
if [ -f "check_env.py" ]; then chmod +x check_env.py; fi

echo "------------------------------------------------"
echo "✅ SETUP COMPLETE!"
echo "------------------------------------------------"
echo "Next Steps:"
echo "1. Build the 'reverse' tool (see README.md Step 1)"
echo "2. Run the app: python3 DecryptCococas.py"
echo "3. Go to Settings in the app to set your paths."