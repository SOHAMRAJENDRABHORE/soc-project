"""Process telemetry. Cross-platform via psutil."""
from __future__ import annotations

import psutil
from shared.logger import get_logger

log = get_logger(__name__)


def run(params: dict) -> dict:
    """
    Collect running processes.
    params:
      filter_suspicious (bool, default True): if True, only return processes
        that look interesting (running from temp paths, no parent, etc.)
      include_full (bool, default False): include the full list as well
    """
    filter_suspicious = params.get("filter_suspicious", True)
    include_full = params.get("include_full", False)

    all_procs: list[dict] = []
    suspicious_indicators = (
        "\\temp\\", "\\appdata\\local\\temp\\", "/tmp/", "/var/tmp/",
        "\\users\\public\\", "\\windows\\debug\\",
    )

    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline",
                                  "username", "create_time", "status"]):
        try:
            info = p.info.copy()
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            exe = (info.get("exe") or "").lower()
            cmd = (info.get("cmdline") or "").lower()

            is_susp = (
                any(s in exe for s in suspicious_indicators)
                or any(s in cmd for s in suspicious_indicators)
                or "powershell" in cmd and ("-encodedcommand" in cmd or "-enc " in cmd)
                or "wmic" in cmd and "process" in cmd and "call create" in cmd
            )
            info["suspicious"] = is_susp
            all_procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    suspicious = [p for p in all_procs if p["suspicious"]]
    result = {
        "total_processes": len(all_procs),
        "suspicious_count": len(suspicious),
        "suspicious_processes": suspicious,
    }
    if include_full or not filter_suspicious:
        result["all_processes"] = all_procs
    return result
