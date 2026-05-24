"""
Deeper Volatility 3 analysis. Adds plugins beyond the basic pslist/netscan.

Targets the same SAMPLE_MEMORY_DUMP as memory.py. Runs additional plugins:

  windows.dlllist     — DLLs loaded into each process
  windows.handles     — open file/registry/mutex handles per process
  windows.registry.hivelist — registry hives loaded in memory
  windows.cmdline     — full process command lines
  windows.svcscan     — Windows services in memory

Linux equivalents:
  linux.lsmod         — loaded kernel modules
  linux.lsof          — open files
  linux.bash          — bash command history from memory

Slower than the basic memory module (each plugin = 30-60s on a small dump).
Run only for HIGH/CRITICAL severity to keep pipeline tolerable.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from shared.config import settings
from shared.logger import get_logger

log = get_logger(__name__)


WINDOWS_DEEP_PLUGINS = [
    "windows.dlllist",
    "windows.handles",
    "windows.cmdline",
    "windows.svcscan",
    "windows.registry.hivelist",
]
LINUX_DEEP_PLUGINS = [
    "linux.lsmod",
    "linux.lsof",
    "linux.bash",
]


def _vol_cmd() -> list[str]:
    binary = settings.VOLATILITY_BINARY or "vol"
    if shutil.which(binary):
        return [binary]
    return [sys.executable, "-m", "volatility3"]


def _run_plugin(dump_path: str, plugin: str, timeout: int = 240) -> dict:
    cmd = _vol_cmd() + ["-r", "json", "-f", dump_path, plugin]
    log.info(f"[deep_memory] {plugin}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return {
                "plugin": plugin, "success": False,
                "error": (proc.stderr or proc.stdout)[:2000],
            }
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            parsed = {"raw_output": proc.stdout[:5000]}
        if isinstance(parsed, list):
            parsed = parsed[:100]
        return {"plugin": plugin, "success": True, "rows": parsed}
    except subprocess.TimeoutExpired:
        return {"plugin": plugin, "success": False, "error": f"Timeout after {timeout}s"}
    except FileNotFoundError:
        return {"plugin": plugin, "success": False,
                "error": "Volatility binary not found"}
    except Exception as e:
        return {"plugin": plugin, "success": False, "error": str(e)}


def run(params: dict) -> dict:
    """
    params:
      dump_path: path to memory dump (defaults to SAMPLE_MEMORY_DUMP)
      dump_os: 'windows' | 'linux'
      plugins: optional override list
    """
    dump_path = params.get("dump_path") or settings.SAMPLE_MEMORY_DUMP
    if not dump_path:
        return {"success": False,
                "error": "No memory dump configured (SAMPLE_MEMORY_DUMP)"}
    if not Path(dump_path).exists():
        return {"success": False, "error": f"Dump not found: {dump_path}"}

    dump_os = (params.get("dump_os") or "windows").lower()
    plugins = params.get("plugins") or (
        WINDOWS_DEEP_PLUGINS if dump_os == "windows" else LINUX_DEEP_PLUGINS
    )

    results = [_run_plugin(dump_path, p) for p in plugins]
    return {
        "success": True,
        "dump_path": dump_path,
        "dump_os": dump_os,
        "deep_plugin_results": results,
        "successful_plugins": sum(1 for r in results if r["success"]),
        "failed_plugins": sum(1 for r in results if not r["success"]),
    }
