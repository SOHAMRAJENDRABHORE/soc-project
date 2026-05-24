"""
Persistence checks. OS-aware:
  - Windows: registry Run keys, scheduled tasks, services
  - Linux:   cron, systemd units, ~/.bashrc additions
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from shared.logger import get_logger

log = get_logger(__name__)


def _run_cmd(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"<error: {e}>"


def _windows_persistence() -> dict:
    out: dict = {}
    # Registry Run keys (read-only, no writes)
    reg_paths = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    reg_results = {}
    for p in reg_paths:
        reg_results[p] = _run_cmd(["reg", "query", p], timeout=10)
    out["registry_run_keys"] = reg_results

    # Scheduled tasks (limit output)
    out["scheduled_tasks"] = _run_cmd(["schtasks", "/Query", "/FO", "LIST"], timeout=15)[:5000]
    # Services
    out["services"] = _run_cmd(["sc", "query", "type=", "service", "state=", "all"], timeout=15)[:5000]
    return out


def _linux_persistence() -> dict:
    out: dict = {}
    paths_to_check = [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/systemd/system", "/lib/systemd/system",
        "/etc/init.d", "/etc/rc.local",
    ]
    found: dict[str, list[str]] = {}
    for p in paths_to_check:
        path = Path(p)
        if path.is_dir():
            try:
                found[p] = sorted([f.name for f in path.iterdir() if f.is_file()])[:50]
            except PermissionError:
                found[p] = ["<permission denied>"]
        elif path.is_file():
            try:
                found[p] = path.read_text(errors="replace").splitlines()[:30]
            except PermissionError:
                found[p] = ["<permission denied>"]
    out["filesystem"] = found

    # User cron entries
    out["user_crontab"] = _run_cmd(["crontab", "-l"], timeout=5)

    # Shell rc additions (current user)
    home = Path(os.path.expanduser("~"))
    rc_files = [".bashrc", ".bash_profile", ".profile", ".zshrc"]
    shell_rcs = {}
    for rc in rc_files:
        f = home / rc
        if f.exists():
            try:
                lines = f.read_text(errors="replace").splitlines()
                # Look for suspicious-ish lines (curl|wget|nc|bash -i)
                susp = [l for l in lines if any(
                    k in l for k in ("curl ", "wget ", " nc ", "bash -i", "/dev/tcp")
                )]
                shell_rcs[rc] = {"total_lines": len(lines), "suspicious_lines": susp}
            except Exception as e:
                shell_rcs[rc] = {"error": str(e)}
    out["shell_rc_files"] = shell_rcs

    # systemctl list of enabled units
    out["systemd_enabled"] = _run_cmd(
        ["systemctl", "list-unit-files", "--state=enabled", "--no-pager"], timeout=10
    )[:5000]
    return out


def run(params: dict) -> dict:
    sys = platform.system()
    if sys == "Windows":
        return {"os": sys, "persistence": _windows_persistence()}
    if sys == "Linux":
        return {"os": sys, "persistence": _linux_persistence()}
    if sys == "Darwin":
        # Minimal macOS support
        return {"os": sys, "persistence": {
            "launch_agents": _run_cmd(["ls", "-la", os.path.expanduser("~/Library/LaunchAgents")]),
            "launch_daemons": _run_cmd(["ls", "-la", "/Library/LaunchDaemons"]),
        }}
    return {"os": sys, "error": "Unsupported OS"}
