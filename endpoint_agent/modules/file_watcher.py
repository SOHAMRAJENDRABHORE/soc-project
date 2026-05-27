"""
Real-time file system watcher.

Monitors configured directories for new executables/scripts.
Pipeline:
  new file detected → wait for write to finish → YARA scan
  if YARA hits → Ghidra / binary_re analysis
  → report finding to central server

Runs as a background thread inside the endpoint agent.
"""
from __future__ import annotations

import hashlib
import os
import platform
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from shared.logger import get_logger

log = get_logger(__name__)

# File extensions to watch (Windows)
_WIN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".hta", ".scr", ".pif", ".com",
    ".jar", ".msi", ".tmp",
}

# File extensions to watch (Linux/macOS additions)
_UNIX_EXTENSIONS = {
    ".sh", ".py", ".pl", ".rb", ".php", ".elf",
    ".so", ".dylib", ".ko", ".out",
}

WATCH_EXTENSIONS = _WIN_EXTENSIONS | _UNIX_EXTENSIONS

# Default directories to watch (platform-aware)
def _default_watch_dirs() -> list[str]:
    if platform.system() == "Windows":
        dirs = [
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            os.environ.get("TMP", "C:\\Windows\\Temp"),
            os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\User"), "Downloads"),
            os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp"),
            "C:\\Windows\\Temp",
        ]
    else:
        dirs = [
            "/tmp", "/var/tmp", "/dev/shm",
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "/usr/local/bin",  # watch for new bins dropped here
        ]
    return [d for d in dirs if d and Path(d).exists()]


def _file_sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _is_executable(path: str) -> bool:
    """Return True if file has executable bit set (Linux/macOS)."""
    try:
        return bool(os.stat(path).st_mode & 0o111)
    except OSError:
        return False


def _wait_for_file_ready(path: str, timeout: int = 10) -> bool:
    """Wait until the file stops growing (write finished)."""
    deadline = time.time() + timeout
    last_size = -1
    while time.time() < deadline:
        try:
            size = os.path.getsize(path)
            if size == last_size and size > 0:
                return True
            last_size = size
        except OSError:
            return False
        time.sleep(0.5)
    return last_size > 0


class FileWatcher:
    """
    Watches a list of directories for new suspicious files.
    Calls on_finding(finding_dict) for each detected threat.
    """

    def __init__(self, watch_dirs: list[str] | None = None,
                 on_finding: Callable[[dict], None] | None = None):
        self._dirs = watch_dirs or _default_watch_dirs()
        self._on_finding = on_finding or (lambda f: None)
        self._seen: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        # Pre-populate seen set so we don't alert on existing files
        for d in self._dirs:
            try:
                for f in Path(d).rglob("*"):
                    if f.is_file():
                        self._seen.add(str(f))
            except Exception:
                pass
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="file-watcher")
        self._thread.start()
        log.info(f"[FileWatcher] Started — watching {len(self._dirs)} dir(s): {self._dirs}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[FileWatcher] Stopped")

    def _run(self):
        while not self._stop.is_set():
            for watch_dir in self._dirs:
                try:
                    self._scan_dir(watch_dir)
                except Exception as e:
                    log.debug(f"[FileWatcher] scan error in {watch_dir}: {e}")
            self._stop.wait(3)  # poll every 3 seconds

    def _scan_dir(self, directory: str):
        try:
            for entry in os.scandir(directory):
                if self._stop.is_set():
                    return
                if not entry.is_file(follow_symlinks=False):
                    continue
                path = entry.path
                if path in self._seen:
                    continue
                self._seen.add(path)
                ext = Path(path).suffix.lower()
                if ext in WATCH_EXTENSIONS:
                    threading.Thread(target=self._analyse, args=(path,),
                                     daemon=True).start()
                elif not ext and platform.system() != "Windows":
                    # On Linux/macOS: no extension but executable bit set → likely ELF
                    if _is_executable(path):
                        threading.Thread(target=self._analyse, args=(path,),
                                         daemon=True).start()
        except PermissionError:
            pass

    def _analyse(self, path: str):
        log.info(f"[FileWatcher] New file: {path}")

        if not _wait_for_file_ready(path):
            log.warning(f"[FileWatcher] File not ready or empty: {path}")
            return

        sha256 = _file_sha256(path)
        yara_result = self._run_yara(path)
        yara_hits = yara_result.get("matches", []) or yara_result.get("matched_rules", [])

        ghidra_result = None
        if yara_hits:
            log.info(f"[FileWatcher] YARA hit on {path} — running Ghidra analysis")
            ghidra_result = self._run_ghidra(path)

        severity = "critical" if len(yara_hits) >= 3 else \
                   "high" if yara_hits else "low"

        finding = {
            "source": "file_watcher",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "file_path": path,
            "sha256": sha256,
            "file_size": os.path.getsize(path) if os.path.exists(path) else 0,
            "yara_hits": len(yara_hits),
            "yara_result": yara_result,
            "ghidra_result": ghidra_result,
            "title": f"Suspicious file: {Path(path).name}",
            "description": (
                f"New executable detected in watched directory.\n"
                f"SHA256: {sha256}\n"
                f"YARA matches: {len(yara_hits)}\n"
                f"Path: {path}"
            ),
        }
        self._on_finding(finding)

    def _run_yara(self, path: str) -> dict:
        try:
            from endpoint_agent.modules.yara_scan import run as yara_run
            return yara_run({"paths": [path]})
        except Exception as e:
            return {"error": str(e), "matches": []}

    def _run_ghidra(self, path: str) -> dict:
        try:
            from endpoint_agent.modules.binary_re import run as ghidra_run
            return ghidra_run({"binary_path": path, "timeout_seconds": 120})
        except Exception as e:
            return {"error": str(e)}
