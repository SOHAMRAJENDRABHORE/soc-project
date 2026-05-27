#!/usr/bin/env bash
# install_linux.sh — Set up the SOC Endpoint Agent on Linux (no binary needed)
#
# Usage:
#   chmod +x install_linux.sh
#   ./install_linux.sh
#
# What it does:
#   1. Installs system packages (Python3, Tk, pip)
#   2. Creates a virtualenv in ./venv
#   3. Installs Python requirements
#   4. Creates a launcher script at ~/bin/soc-endpoint-agent
#
# After running, start the GUI app with:
#   soc-endpoint-agent
#
# Or start the headless agent (no GUI) with:
#   soc-endpoint-agent --headless

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
LAUNCHER="$HOME/bin/soc-endpoint-agent"

# ── Detect distro and install system packages ─────────────────────────────────
echo "=== SOC Endpoint Agent — Linux Installer ==="
echo ""

install_system_deps() {
    if command -v apt-get &>/dev/null; then
        echo "[*] Detected Debian/Ubuntu — installing system packages..."
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip python3-venv python3-tk \
            libgl1 libglib2.0-0 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        echo "[*] Detected Fedora/RHEL — installing system packages..."
        sudo dnf install -y python3 python3-pip python3-tkinter 2>/dev/null || true
    elif command -v pacman &>/dev/null; then
        echo "[*] Detected Arch Linux — installing system packages..."
        sudo pacman -Sy --noconfirm python python-pip tk 2>/dev/null || true
    else
        echo "[!] Unknown distro — skipping system package install."
        echo "    Make sure Python 3.10+, pip, and tkinter are installed."
    fi
}

install_system_deps

# ── Create virtualenv ─────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
else
    echo "[*] Virtual environment already exists at $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# ── Install Python requirements ───────────────────────────────────────────────
echo "[*] Installing Python requirements..."
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q

# Optional forensics libs (best-effort — won't fail install if unavailable)
echo "[*] Attempting to install optional forensics libraries..."
pip install volatility3 yara-python 2>/dev/null || \
    echo "[!] volatility3 or yara-python unavailable — forensics features will be limited."

deactivate

# ── Create launcher script ────────────────────────────────────────────────────
mkdir -p "$HOME/bin"

cat > "$LAUNCHER" << EOF
#!/usr/bin/env bash
# SOC Endpoint Agent launcher
SCRIPT_DIR="$SCRIPT_DIR"
source "\$SCRIPT_DIR/venv/bin/activate"

if [[ "\${1:-}" == "--headless" ]]; then
    # Run headless agent (no GUI) — useful for servers
    cd "\$SCRIPT_DIR"
    python -m endpoint_agent.agent
else
    # Run GUI app
    cd "\$SCRIPT_DIR"
    python endpoint_app/app.py
fi
EOF

chmod +x "$LAUNCHER"

# Make sure ~/bin is in PATH
if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
    echo ""
    echo "[!] Add ~/bin to your PATH by adding this line to ~/.bashrc or ~/.profile:"
    echo "    export PATH=\"\$HOME/bin:\$PATH\""
    echo "    Then run:  source ~/.bashrc"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Installation complete!"
echo ""
echo "  Start GUI app:      soc-endpoint-agent"
echo "  Start headless:     soc-endpoint-agent --headless"
echo ""
echo "  Before first run, copy .env to this directory and set:"
echo "    CENTRAL_SERVER_URL=https://your-ngrok-url"
echo "    AGENT_AUTH_TOKEN=your-token"
echo "============================================================"
