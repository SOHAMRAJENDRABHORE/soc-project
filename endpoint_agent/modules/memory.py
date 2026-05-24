"""
Volatility 3 wrapper. Runs real Volatility against a memory dump.

For the demo, we use a pre-captured sample dump (path in SAMPLE_MEMORY_DUMP env var).
In production, the agent would capture live memory first (winpmem on Windows, LiME on Linux).

Plugins we run by default:
  windows.pslist  — process listing
  windows.netscan — network artifacts
  windows.cmdline — command lines
  windows.malfind — injected code detection

For Linux dumps swap windows.* for linux.*.
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


DEFAULT_WINDOWS_PLUGINS = ["windows.pslist", "windows.netscan", "windows.cmdline", "windows.malfind"]
DEFAULT_LINUX_PLUGINS = ["linux.pslist", "linux.bash", "linux.malfind"]


def _vol_cmd() -> list[str]:
    """Locate the volatility binary."""
    candidate = settings.VOLATILITY_BINARY or "vol"
    if shutil.which(candidate):
        return [candidate]
    # Fallback: use the current interpreter so it works on both Linux (python3) and Windows
    return [sys.executable, "-m", "volatility3"]


def _run_plugin(dump_path: str, plugin: str, timeout: int = 180) -> dict:
    cmd = _vol_cmd() + ["-r", "json", "-f", dump_path, plugin]
    log.info(f"Running Volatility: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return {
                "plugin": plugin,
                "success": False,
                "error": (proc.stderr or proc.stdout)[:2000],
            }
        # Volatility prints JSON to stdout with -r json
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # Some plugins emit non-JSON; return raw
            parsed = {"raw_output": proc.stdout[:10000]}
        # Cap rows so we don't blow past LLM context later
        if isinstance(parsed, list):
            parsed = parsed[:200]
        return {"plugin": plugin, "success": True, "rows": parsed}
    except subprocess.TimeoutExpired:
        return {"plugin": plugin, "success": False, "error": f"Timeout after {timeout}s"}
    except FileNotFoundError:
        return {"plugin": plugin, "success": False,
                "error": "Volatility binary not found. Set VOLATILITY_BINARY in .env."}
    except Exception as e:
        return {"plugin": plugin, "success": False, "error": str(e)}


def run(params: dict) -> dict:
    """
    params:
      dump_path: path to memory dump. Defaults to SAMPLE_MEMORY_DUMP env var.
      plugins: list of Volatility plugins. If empty, auto-pick based on dump_os.
      dump_os: "windows" | "linux" (helps plugin selection)
    """
    dump_path = params.get("dump_path") or settings.SAMPLE_MEMORY_DUMP
    if not dump_path:
        return {
            "success": False,
            "error": "No memory dump configured. Set SAMPLE_MEMORY_DUMP in .env "
                     "or pass dump_path in params.",
        }
    if not Path(dump_path).exists():
        return {"success": False, "error": f"Dump not found: {dump_path}"}

    dump_os = (params.get("dump_os") or "windows").lower()
    plugins = params.get("plugins") or (
        DEFAULT_WINDOWS_PLUGINS if dump_os == "windows" else DEFAULT_LINUX_PLUGINS
    )

    log.info(f"Analyzing memory dump: {dump_path} (os={dump_os}, plugins={plugins})")
    results = [_run_plugin(dump_path, p) for p in plugins]

    return {
        "dump_path": dump_path,
        "dump_os": dump_os,
        "plugin_results": results,
        "successful_plugins": sum(1 for r in results if r["success"]),
        "failed_plugins": sum(1 for r in results if not r["success"]),
    }
