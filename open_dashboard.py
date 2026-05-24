"""
Quick launcher: opens the SOC dashboard in your default browser.

Usage:
  python open_dashboard.py           # opens dashboard directly from file
  python open_dashboard.py --server  # assumes central server is running on :8080
"""
import sys
import webbrowser
from pathlib import Path

DASHBOARD = Path(__file__).parent / "frontend" / "dashboard" / "index.html"
SERVER_URL = "http://localhost:8080/ui/index.html"

if "--server" in sys.argv:
    print(f"Opening dashboard via server: {SERVER_URL}")
    webbrowser.open(SERVER_URL)
else:
    url = DASHBOARD.as_uri()
    print(f"Opening dashboard directly: {url}")
    print("Tip: use --server flag if the central server is running on :8080")
    webbrowser.open(url)
