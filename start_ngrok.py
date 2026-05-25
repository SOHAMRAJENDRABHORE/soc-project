"""
Start the central server and expose it publicly via ngrok.

Usage:
    python start_ngrok.py                   # uses NGROK_AUTHTOKEN from .env
    python start_ngrok.py --domain my-domain.ngrok-free.app   # use your free static domain

After it starts, copy the ngrok URL and:
  - On the remote endpoint agent machine: set CENTRAL_SERVER_URL=<ngrok_url> in .env
  - In the dashboard Settings panel: paste the ngrok URL as the Server URL
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")


def main():
    parser = argparse.ArgumentParser(description="Start SOC server + ngrok tunnel")
    parser.add_argument("--domain", default=os.getenv("NGROK_DOMAIN", ""),
                        help="Your ngrok static domain (e.g. my-name.ngrok-free.app)")
    parser.add_argument("--port", type=int, default=8080, help="Server port (default 8080)")
    args = parser.parse_args()

    try:
        from pyngrok import ngrok, conf
    except ImportError:
        print("[ERROR] pyngrok not installed. Run:  pip install pyngrok")
        sys.exit(1)

    # Configure ngrok auth token if provided
    auth_token = os.getenv("NGROK_AUTHTOKEN", "")
    if auth_token:
        conf.get_default().auth_token = auth_token
    else:
        print("[WARN] NGROK_AUTHTOKEN not set in .env — using ngrok without auth (limited).")
        print("       Sign up free at https://dashboard.ngrok.com and add your token to .env")
        print()

    # Start the central server in a subprocess
    print(f"[1/2] Starting central server on port {args.port}...")
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "central_server.server:app",
         "--host", "0.0.0.0", "--port", str(args.port)],
        cwd=str(PROJECT_ROOT),
    )
    time.sleep(2)  # give uvicorn a moment to bind

    if server_proc.poll() is not None:
        print("[ERROR] Server failed to start. Check the output above.")
        sys.exit(1)

    # Open ngrok tunnel
    print("[2/2] Opening ngrok tunnel...")
    try:
        if args.domain:
            tunnel = ngrok.connect(args.port, domain=args.domain)
        else:
            tunnel = ngrok.connect(args.port)
    except Exception as e:
        print(f"[ERROR] ngrok tunnel failed: {e}")
        server_proc.terminate()
        sys.exit(1)

    public_url = tunnel.public_url
    # ngrok always gives https for http tunnels when auth token is set
    if public_url.startswith("http://"):
        public_url = public_url.replace("http://", "https://", 1)

    print()
    print("=" * 60)
    print("  SOC Server is LIVE via ngrok!")
    print("=" * 60)
    print(f"  Public URL : {public_url}")
    print(f"  Local URL  : http://localhost:{args.port}")
    print()
    print("  --> Dashboard: open in browser:")
    print(f"      {public_url}/ui/index.html")
    print()
    print("  --> On the remote endpoint agent machine, set in .env:")
    print(f"      CENTRAL_SERVER_URL={public_url}")
    print()
    print("  --> In the dashboard Settings panel, set Server URL to:")
    print(f"      {public_url}")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    # Handle Ctrl+C gracefully
    def _shutdown(sig, frame):
        print("\n[Stopping] Closing ngrok tunnel and server...")
        ngrok.disconnect(tunnel.public_url)
        ngrok.kill()
        server_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep alive
    while True:
        if server_proc.poll() is not None:
            print("[ERROR] Server process died unexpectedly.")
            ngrok.kill()
            sys.exit(1)
        time.sleep(3)


if __name__ == "__main__":
    main()
