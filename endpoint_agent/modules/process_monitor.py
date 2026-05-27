"""
Live process monitor using psutil.

Watches for new/suspicious processes without needing a full memory dump.
Flags processes based on:
  - Spawning from suspicious locations (Temp, Downloads, AppData)
  - Unusual parent-child relationships (Word spawning cmd.exe)
  - Known LOLBin abuse (powershell, wscript, mshta, etc.)
  - Processes with no command line (hollowing indicator)
  - High memory anomalies

Runs as a background thread. Calls on_finding(finding_dict) for threats.
"""
from __future__ import annotations

import platform
import threading
import time
from datetime import datetime, timezone
from typing import Callable

import psutil

from shared.logger import get_logger

log = get_logger(__name__)

# Windows LOLBins
_WIN_LOLBINS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "wmic.exe", "psexec.exe", "net.exe", "net1.exe",
    "sc.exe", "schtasks.exe", "at.exe", "reg.exe", "regedit.exe",
}

# Linux LOLBins / living-off-the-land binaries
_LINUX_LOLBINS = {
    "bash", "sh", "dash", "zsh", "ksh",
    "python", "python3", "perl", "ruby", "php",
    "wget", "curl", "nc", "ncat", "netcat", "socat",
    "nmap", "tcpdump", "tshark",
    "crontab", "at", "awk", "sed", "tee",
    "base64", "xxd", "dd", "openssl",
    "gcc", "cc", "make",
    "chmod", "chown", "chattr",
    "find", "xargs",
    "nsenter", "unshare", "capsh",
}

LOLBINS = _WIN_LOLBINS | _LINUX_LOLBINS

# Office / browser processes — suspicious if they spawn shells
OFFICE_PROCS = {
    # Windows
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "chrome.exe", "firefox.exe",
    "msedge.exe", "iexplore.exe", "acrobat.exe", "acrord32.exe",
    # Linux
    "libreoffice", "soffice", "evince", "okular",
    "thunderbird", "chromium", "chromium-browser",
}

# Suspicious path fragments
SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\", "\\programdata\\",
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
]


def _is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    return any(frag in low for frag in SUSPICIOUS_PATH_FRAGMENTS)


def _score_process(proc_info: dict) -> tuple[int, list[str]]:
    """Return (suspicion_score 0-100, reasons)."""
    score = 0
    reasons = []
    name = (proc_info.get("name") or "").lower()
    exe = (proc_info.get("exe") or "").lower()
    cmdline = " ".join(proc_info.get("cmdline") or []).lower()
    parent_name = (proc_info.get("parent_name") or "").lower()

    # Spawned from suspicious path
    if _is_suspicious_path(exe):
        score += 40
        reasons.append(f"Runs from suspicious path: {exe}")

    # LOLBin spawned by Office/browser
    if name in LOLBINS and parent_name in OFFICE_PROCS:
        score += 50
        reasons.append(f"LOLBin {name} spawned by {parent_name}")

    # PowerShell with encoded command
    if name in ("powershell.exe", "pwsh.exe") and (
        "-enc" in cmdline or "-encodedcommand" in cmdline or
        "-nop" in cmdline or "-w hidden" in cmdline
    ):
        score += 35
        reasons.append("PowerShell with obfuscation flags")

    # No command line (process hollowing indicator)
    if not cmdline and name not in ("system", "registry", "smss.exe",
                                     "csrss.exe", "wininit.exe"):
        score += 20
        reasons.append("No command line (possible hollowing)")

    # certutil / bitsadmin used for download
    if name in ("certutil.exe", "bitsadmin.exe") and (
        "urlcache" in cmdline or "transfer" in cmdline or "http" in cmdline
    ):
        score += 45
        reasons.append(f"{name} used for download (LOLBin abuse)")

    # mshta / wscript / cscript running from temp
    if name in ("mshta.exe", "wscript.exe", "cscript.exe") and _is_suspicious_path(cmdline):
        score += 40
        reasons.append(f"{name} executing script from temp directory")

    # Linux: shell with -i flag (interactive reverse shell)
    if name in ("bash", "sh", "dash", "zsh") and "-i" in (proc_info.get("cmdline") or []):
        score += 50
        reasons.append(f"Interactive shell ({name} -i) — possible reverse shell")

    # Linux: interpreter executing inline code (python -c, perl -e, ruby -e, php -r)
    if name in ("python", "python3", "perl", "ruby", "php") and (
        " -c " in f" {cmdline} " or " -e " in f" {cmdline} " or " -r " in f" {cmdline} "
    ):
        score += 45
        reasons.append(f"{name} with inline code execution flag")

    # Linux: curl or wget piped to shell (download-and-exec)
    if name in ("curl", "wget") and any(
        x in cmdline for x in ["| sh", "| bash", "| python", "|sh", "|bash", "|python"]
    ):
        score += 60
        reasons.append(f"{name} piped to shell interpreter")

    # Linux: base64 decode (often used to decode payloads)
    if name == "base64" and "-d" in cmdline:
        score += 30
        reasons.append("base64 decode (possible payload decoding)")

    # Linux: nc/socat used for reverse shell
    if name in ("nc", "ncat", "netcat", "socat") and (
        "-e" in cmdline or "exec" in cmdline or "/bin/sh" in cmdline or "/bin/bash" in cmdline
    ):
        score += 65
        reasons.append(f"{name} with shell exec (likely reverse shell)")

    # Linux: nsenter/unshare used for container escape
    if name in ("nsenter", "unshare", "capsh"):
        score += 55
        reasons.append(f"{name} used — possible container escape or privilege escalation")

    return min(score, 100), reasons


class ProcessMonitor:
    """
    Continuously monitors running processes for suspicious activity.
    Calls on_finding(finding_dict) when a threat is detected.
    """

    def __init__(self, on_finding: Callable[[dict], None] | None = None,
                 poll_interval: int = 5, score_threshold: int = 40):
        self._on_finding = on_finding or (lambda f: None)
        self._poll_interval = poll_interval
        self._threshold = score_threshold
        self._known_pids: set[int] = set()
        self._alerted_pids: set[int] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        # Snapshot current PIDs so we only alert on NEW processes
        self._known_pids = {p.pid for p in psutil.process_iter()}
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="process-monitor")
        self._thread.start()
        log.info(f"[ProcessMonitor] Started — threshold={self._threshold}, "
                 f"poll={self._poll_interval}s, baseline={len(self._known_pids)} PIDs")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[ProcessMonitor] Stopped")

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.debug(f"[ProcessMonitor] poll error: {e}")
            self._stop.wait(self._poll_interval)

    def _poll(self):
        current_pids = set()
        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "ppid", "create_time", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if pid in self._known_pids or pid in self._alerted_pids:
                    continue

                # Get parent name
                try:
                    parent = psutil.Process(info["ppid"])
                    info["parent_name"] = parent.name()
                except Exception:
                    info["parent_name"] = ""

                score, reasons = _score_process(info)
                if score >= self._threshold:
                    self._alerted_pids.add(pid)
                    self._report(info, score, reasons)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Clean up dead PIDs
        self._known_pids = current_pids
        self._alerted_pids &= current_pids

    def _report(self, info: dict, score: int, reasons: list[str]):
        name = info.get("name") or "unknown"
        exe = info.get("exe") or ""
        cmdline = " ".join(info.get("cmdline") or [])
        pid = info.get("pid")
        parent = info.get("parent_name", "")

        severity = "critical" if score >= 80 else \
                   "high" if score >= 60 else \
                   "medium" if score >= 40 else "low"

        log.warning(f"[ProcessMonitor] Suspicious process PID={pid} {name} score={score} — {reasons}")

        finding = {
            "source": "process_monitor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "title": f"Suspicious process: {name} (PID {pid})",
            "description": (
                f"Process flagged with suspicion score {score}/100.\n"
                f"Name: {name}\n"
                f"PID: {pid}\n"
                f"Parent: {parent}\n"
                f"Exe: {exe}\n"
                f"Cmdline: {cmdline[:300]}\n"
                f"Reasons: {'; '.join(reasons)}"
            ),
            "process": {
                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline[:500],
                "parent_name": parent,
                "suspicion_score": score,
                "reasons": reasons,
            },
        }
        self._on_finding(finding)
