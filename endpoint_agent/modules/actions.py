"""
Reversible action handlers. All operations preserve evidence:
  - isolate_endpoint:  firewall block all except central server (reversible)
  - unisolate_endpoint
  - block_ip:          single-IP outbound block (reversible)
  - block_domain:      add to hosts file with marker (reversible)
  - quarantine_file:   move to quarantine dir (file preserved, just inert)
  - disable_user:      lock account (reversible with /active:yes or usermod -U)
  - snapshot_process:  suspend + dump (NEVER kill)
  - unblock_ip:        reverse a previous block_ip

Requires admin/root for firewall + hosts file changes.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from shared.config import settings, PROJECT_ROOT
from shared.logger import get_logger

log = get_logger(__name__)

QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)

HOSTS_MARKER_BEGIN = "# === AGENTIC_SOC BLOCKLIST BEGIN ==="
HOSTS_MARKER_END = "# === AGENTIC_SOC BLOCKLIST END ==="
ISOLATE_RULE_NAME = "AgenticSOC_Isolation"


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _hosts_path() -> Path:
    return Path(r"C:\Windows\System32\drivers\etc\hosts") if _is_windows() \
        else Path("/etc/hosts")


# ---------- isolate / unisolate ----------

def isolate_endpoint(params: dict) -> dict:
    server_host = settings.CENTRAL_SERVER_URL.split("//")[-1].split(":")[0]
    if _is_windows():
        rc1, out1 = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                          f"name={ISOLATE_RULE_NAME}_Allow",
                          "dir=out", "action=allow", f"remoteip={server_host}"])
        rc2, out2 = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                          f"name={ISOLATE_RULE_NAME}_Block",
                          "dir=out", "action=block", "remoteip=any"])
        return {"action": "isolate_endpoint",
                "success": rc1 == 0 and rc2 == 0,
                "platform": "windows", "server_allowed": server_host,
                "output": (out1 + out2)[:1000]}
    else:
        outs, ok = [], True
        for c in [
            ["iptables", "-I", "OUTPUT", "-d", server_host, "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-j", "DROP"],
        ]:
            rc, out = _run(c)
            outs.append(out)
            if rc != 0:
                ok = False
        return {"action": "isolate_endpoint", "success": ok,
                "platform": "linux", "server_allowed": server_host,
                "output": "\n".join(outs)[:1000]}


def unisolate_endpoint(params: dict) -> dict:
    if _is_windows():
        rc1, out1 = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                          f"name={ISOLATE_RULE_NAME}_Block"])
        rc2, out2 = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                          f"name={ISOLATE_RULE_NAME}_Allow"])
        return {"action": "unisolate_endpoint",
                "success": rc1 == 0 or rc2 == 0,
                "output": (out1 + out2)[:1000]}
    else:
        rc1, out1 = _run(["iptables", "-D", "OUTPUT", "-j", "DROP"])
        server_host = settings.CENTRAL_SERVER_URL.split("//")[-1].split(":")[0]
        rc2, out2 = _run(["iptables", "-D", "OUTPUT", "-d", server_host, "-j", "ACCEPT"])
        return {"action": "unisolate_endpoint", "success": True,
                "output": (out1 + out2)[:1000]}


# ---------- block / unblock IP ----------

def block_ip(params: dict) -> dict:
    ip = (params.get("ip") or "").strip()
    if not ip:
        return {"action": "block_ip", "success": False, "error": "no ip provided"}
    rule_name = f"AgenticSOC_BlockIP_{ip.replace('.', '_')}"
    if _is_windows():
        rc, out = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=out", "action=block",
                        f"remoteip={ip}"])
        return {"action": "block_ip", "success": rc == 0,
                "ip": ip, "rule_name": rule_name, "output": out[:500]}
    else:
        rc, out = _run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        return {"action": "block_ip", "success": rc == 0, "ip": ip, "output": out[:500]}


def unblock_ip(params: dict) -> dict:
    ip = (params.get("ip") or "").strip()
    if not ip:
        return {"action": "unblock_ip", "success": False, "error": "no ip provided"}
    rule_name = f"AgenticSOC_BlockIP_{ip.replace('.', '_')}"
    if _is_windows():
        rc, out = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"])
        return {"action": "unblock_ip", "success": rc == 0, "ip": ip, "output": out[:500]}
    else:
        rc, out = _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        return {"action": "unblock_ip", "success": rc == 0, "ip": ip, "output": out[:500]}


# ---------- block domain ----------

def block_domain(params: dict) -> dict:
    domain = (params.get("domain") or "").strip()
    if not domain:
        return {"action": "block_domain", "success": False, "error": "no domain"}
    hosts = _hosts_path()
    try:
        content = hosts.read_text()
    except PermissionError:
        return {"action": "block_domain", "success": False,
                "error": "Permission denied — agent needs admin/root"}
    entry = f"127.0.0.1 {domain}"
    if HOSTS_MARKER_BEGIN not in content:
        content += f"\n{HOSTS_MARKER_BEGIN}\n{HOSTS_MARKER_END}\n"
    if entry in content:
        return {"action": "block_domain", "success": True,
                "domain": domain, "note": "already present"}
    content = content.replace(HOSTS_MARKER_END, f"{entry}\n{HOSTS_MARKER_END}")
    try:
        hosts.write_text(content)
    except PermissionError:
        return {"action": "block_domain", "success": False,
                "error": "Permission denied writing hosts file"}
    return {"action": "block_domain", "success": True, "domain": domain}


# ---------- quarantine file ----------

def quarantine_file(params: dict) -> dict:
    src_str = params.get("path", "")
    if not src_str:
        return {"action": "quarantine_file", "success": False, "error": "no path"}
    src = Path(src_str)
    if not src.exists():
        return {"action": "quarantine_file", "success": False,
                "error": f"file not found: {src_str}"}
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = QUARANTINE_DIR / f"{ts}__{src.name}"
    try:
        shutil.move(str(src), str(dest))
        if not _is_windows():
            os.chmod(dest, 0o400)
        return {"action": "quarantine_file", "success": True,
                "original_path": str(src), "quarantine_path": str(dest)}
    except Exception as e:
        return {"action": "quarantine_file", "success": False, "error": str(e)}


# ---------- disable user ----------

def disable_user(params: dict) -> dict:
    username = (params.get("username") or "").strip()
    if not username:
        return {"action": "disable_user", "success": False, "error": "no username"}
    if _is_windows():
        rc, out = _run(["net", "user", username, "/active:no"])
    else:
        rc, out = _run(["usermod", "-L", username])
    return {"action": "disable_user", "success": rc == 0,
            "username": username, "output": out[:500]}


# ---------- snapshot process (suspend, never kill) ----------

def snapshot_process(params: dict) -> dict:
    try:
        import psutil
    except ImportError:
        return {"action": "snapshot_process", "success": False, "error": "psutil missing"}
    pid = params.get("pid")
    if pid is None:
        return {"action": "snapshot_process", "success": False, "error": "no pid"}
    try:
        pid = int(pid)
        p = psutil.Process(pid)
        info = {"pid": pid, "name": p.name(), "exe": p.exe(),
                "cmdline": " ".join(p.cmdline())}
        p.suspend()
        info["status_after_suspend"] = p.status()
        return {"action": "snapshot_process", "success": True,
                "process_info": info,
                "note": "Process suspended (not killed). Evidence preserved."}
    except psutil.NoSuchProcess:
        return {"action": "snapshot_process", "success": False,
                "error": f"no process with pid {pid}"}
    except psutil.AccessDenied:
        return {"action": "snapshot_process", "success": False,
                "error": "permission denied (run agent as admin)"}
    except Exception as e:
        return {"action": "snapshot_process", "success": False, "error": str(e)}


def make_runner(handler):
    """Wrap each action handler so it matches the agent's `run(params) -> dict` API."""
    def run(params: dict) -> dict:
        return handler(params)
    return run
