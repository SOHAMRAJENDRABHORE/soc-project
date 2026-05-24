#!/usr/bin/env bash
# Agentic SOC — Linux startup helper
# Run this from the project root: bash start_linux.sh [command]
#
# Commands:
#   setup      — create venv and install dependencies
#   server     — start the central server (port 8080)
#   agent      — start the endpoint agent (connects to central server)
#   workflow   — run the full pipeline against a sample alert
#   dashboard  — open the web dashboard (http://localhost:8080/ui/)
#   all        — start server + agent in background, then show logs
#
# Example (first time):
#   bash start_linux.sh setup
#   bash start_linux.sh server   # in terminal 1
#   bash start_linux.sh agent    # in terminal 2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv"
PYTHON="$VENV/bin/python3"
PIP="$VENV/bin/pip"

# ─── helpers ──────────────────────────────────────────────────────────────────

_check_python() {
    if ! command -v python3 &>/dev/null; then
        echo "ERROR: python3 not found. Install it with: sudo apt install python3 python3-venv python3-pip"
        exit 1
    fi
}

_activate() {
    if [ ! -f "$PYTHON" ]; then
        echo "ERROR: Virtual environment not found. Run: bash start_linux.sh setup"
        exit 1
    fi
}

_check_env() {
    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        echo "WARNING: .env file not found. Copying from .env.example if it exists..."
        [ -f "$SCRIPT_DIR/.env.example" ] && cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    fi
}

# ─── commands ─────────────────────────────────────────────────────────────────

cmd_setup() {
    _check_python
    echo "==> Creating virtual environment..."
    python3 -m venv "$VENV"
    echo "==> Upgrading pip..."
    "$PIP" install --upgrade pip
    echo "==> Installing dependencies..."
    "$PIP" install -r requirements.txt
    echo ""
    echo "Setup complete. Next steps:"
    echo "  1. Edit .env and fill in your API keys"
    echo "  2. bash start_linux.sh server   (in one terminal)"
    echo "  3. bash start_linux.sh agent    (in another terminal)"
    echo "  4. Open http://localhost:8080/ui/ in your browser"
}

cmd_server() {
    _activate
    _check_env
    echo "==> Starting central server on port 8080..."
    exec "$PYTHON" -m uvicorn central_server.server:app \
        --host 0.0.0.0 --port 8080 --reload
}

cmd_agent() {
    _activate
    _check_env
    echo "==> Starting endpoint agent..."
    exec "$PYTHON" -m endpoint_agent.agent
}

cmd_workflow() {
    _activate
    _check_env
    ALERT_ID="${2:-alert-$(date +%s)}"
    echo "==> Running pipeline for alert: $ALERT_ID"
    "$PYTHON" -m workflow.orchestrator "$@"
}

cmd_dashboard() {
    URL="http://localhost:8080/ui/"
    echo "==> Opening dashboard at $URL"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$URL"
    elif command -v python3 &>/dev/null; then
        python3 -c "import webbrowser; webbrowser.open('$URL')"
    else
        echo "Visit $URL in your browser"
    fi
}

cmd_all() {
    _activate
    _check_env
    echo "==> Starting central server in background (logs: /tmp/soc-server.log)..."
    "$PYTHON" -m uvicorn central_server.server:app \
        --host 0.0.0.0 --port 8080 > /tmp/soc-server.log 2>&1 &
    SERVER_PID=$!
    echo "    Server PID: $SERVER_PID"

    sleep 2

    echo "==> Starting endpoint agent in background (logs: /tmp/soc-agent.log)..."
    "$PYTHON" -m endpoint_agent.agent > /tmp/soc-agent.log 2>&1 &
    AGENT_PID=$!
    echo "    Agent  PID: $AGENT_PID"

    echo ""
    echo "Both processes running. Dashboard: http://localhost:8080/ui/"
    echo "To stop:  kill $SERVER_PID $AGENT_PID"
    echo "Logs:     tail -f /tmp/soc-server.log /tmp/soc-agent.log"
    echo ""
    echo "Following logs (Ctrl-C to stop following — processes keep running):"
    trap "echo 'Detached from logs. Processes still running.'" INT
    tail -f /tmp/soc-server.log /tmp/soc-agent.log
}

# ─── dispatch ─────────────────────────────────────────────────────────────────

COMMAND="${1:-help}"

case "$COMMAND" in
    setup)     cmd_setup ;;
    server)    cmd_server ;;
    agent)     cmd_agent ;;
    workflow)  cmd_workflow "$@" ;;
    dashboard) cmd_dashboard ;;
    all)       cmd_all ;;
    help|--help|-h)
        grep '^#' "$0" | grep -v '!/usr/bin' | sed 's/^# \{0,1\}//'
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Run: bash start_linux.sh help"
        exit 1
        ;;
esac
