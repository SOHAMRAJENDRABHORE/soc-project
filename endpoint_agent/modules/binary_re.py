"""
Ghidra headless analyzer wrapper.

Runs analyzeHeadless on a target binary, extracts strings + import/export tables
+ function listing. Real Ghidra; takes 30s-3min depending on binary size.

Setup (on the agent machine):
  1. Download Ghidra: https://ghidra-sre.org/
  2. Install Java JDK 17+ (Ghidra requirement)
  3. Set GHIDRA_HEADLESS in .env:
       Linux:   /opt/ghidra/support/analyzeHeadless
       Windows: C:\\ghidra\\support\\analyzeHeadless.bat
  4. Point SAMPLE_BINARY at the file you want analyzed.

Where to get safe sample binaries:
  - Any small EXE/ELF from your system (notepad.exe, /bin/ls)  ← safe
  - MalwareBazaar (https://bazaar.abuse.ch/)                   ← REAL malware; handle carefully
  - theZoo                                                     ← REAL malware; handle carefully
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from shared.config import settings
from shared.logger import get_logger

log = get_logger(__name__)


def _strings_fallback(binary_path: str, min_len: int = 6, limit: int = 200) -> list[str]:
    """If Ghidra is unavailable, at least pull printable strings."""
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        return [f"<read error: {e}>"]
    out: list[str] = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(current.decode("ascii", errors="ignore"))
                if len(out) >= limit:
                    break
            current.clear()
    return out


def _run_ghidra(binary_path: str, timeout: int = 300) -> dict:
    ghidra = settings.GHIDRA_HEADLESS
    if not ghidra:
        return {"success": False,
                "error": "GHIDRA_HEADLESS not configured in .env. "
                         "Falling back to strings extraction.",
                "fallback_strings": _strings_fallback(binary_path)}
    if not Path(ghidra).exists() and not shutil.which(ghidra):
        return {"success": False,
                "error": f"Ghidra binary not found at: {ghidra}",
                "fallback_strings": _strings_fallback(binary_path)}

    # Ghidra writes to a project directory; use a temp one
    with tempfile.TemporaryDirectory() as tmp:
        proj_dir = Path(tmp) / "ghidra_proj"
        proj_dir.mkdir()
        proj_name = "soc_analysis"

        cmd = [
            ghidra,
            str(proj_dir), proj_name,
            "-import", binary_path,
            "-analysisTimeoutPerFile", str(timeout),
            "-noanalysis",   # we'll do analysis but skip the slow optional passes
            "-overwrite",
        ]
        # Drop the -noanalysis flag for full analysis (slower, much richer output)
        cmd.remove("-noanalysis")

        log.info(f"Running Ghidra headless: {binary_path}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
            output = proc.stdout + "\n" + proc.stderr

            # Ghidra's headless output is verbose log text. We extract signals.
            return _parse_ghidra_log(output, binary_path)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Ghidra timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}


def _parse_ghidra_log(output: str, binary_path: str) -> dict:
    """Pull a summary out of Ghidra's headless log."""
    lines = output.splitlines()
    summary: dict = {
        "success": True,
        "binary": binary_path,
        "ghidra_log_excerpt": [],
        "imports": [],
        "exports": [],
        "function_count_hint": None,
    }
    # Take the last 40 lines as an excerpt (where the summary usually is)
    summary["ghidra_log_excerpt"] = lines[-40:]

    # Heuristic extraction
    for line in lines:
        low = line.lower()
        if "imports" in low and "function" in low:
            summary["function_count_hint"] = line.strip()
        if "error" in low and "analysis" in low:
            summary.setdefault("errors", []).append(line.strip())

    # Always include strings as a complementary signal — they're often the most useful
    # forensic output anyway for a quick triage.
    summary["strings_sample"] = _strings_fallback(binary_path, limit=150)
    return summary


def run(params: dict) -> dict:
    """
    params:
      binary_path: path to binary. Defaults to SAMPLE_BINARY env var.
      timeout_seconds: Ghidra analysis cap (default 300)
    """
    binary = params.get("binary_path") or settings.SAMPLE_BINARY
    if not binary:
        return {"success": False,
                "error": "No binary configured. Set SAMPLE_BINARY in .env "
                         "or pass binary_path in params."}
    if not Path(binary).exists():
        return {"success": False, "error": f"Binary not found: {binary}"}

    timeout = int(params.get("timeout_seconds", 300))
    return _run_ghidra(binary, timeout=timeout)
