"""
Authentication & session log analysis.

Linux:
  Parses /var/log/auth.log (or /var/log/secure on RHEL-likes).
  Surfaces: failed logins, sudo usage, SSH sessions, new users, password changes.

Windows:
  Uses `wevtutil qe Security` to query the Security log for the same patterns.
  Falls back to a heuristic if not running with admin / wevtutil access.

Returns structured summary the LLM can interpret as suspicious or normal.
"""
from __future__ import annotations

import platform
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from shared.logger import get_logger

log = get_logger(__name__)


# ---------- Linux ----------

_LINUX_AUTH_PATHS = [
    "/var/log/auth.log",       # Debian/Ubuntu
    "/var/log/auth.log.1",
    "/var/log/secure",          # RHEL/CentOS/Fedora
]

# Patterns to surface
_PATTERNS = {
    "failed_password": re.compile(r"Failed password for(?: invalid user)? (\S+) from (\S+)"),
    "accepted_password": re.compile(r"Accepted password for (\S+) from (\S+)"),
    "accepted_publickey": re.compile(r"Accepted publickey for (\S+) from (\S+)"),
    "sudo_command": re.compile(r"sudo:\s+(\S+)\s*:\s*.*COMMAND=(.+)$"),
    "new_user": re.compile(r"new user: name=(\S+),"),
    "password_change": re.compile(r"password changed for (\S+)"),
    "ssh_invalid_user": re.compile(r"Invalid user (\S+) from (\S+)"),
}


def _read_linux_logs(max_lines: int = 5000) -> list[str]:
    """Read the last N lines from the most recent auth log we can find."""
    for p in _LINUX_AUTH_PATHS:
        path = Path(p)
        if not path.exists():
            continue
        try:
            # Use `tail` for efficiency on large files
            r = subprocess.run(
                ["tail", "-n", str(max_lines), str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                return r.stdout.splitlines()
        except Exception as e:
            log.warning(f"Failed to read {p}: {e}")
    return []


def _analyze_linux() -> dict:
    lines = _read_linux_logs()
    if not lines:
        return {
            "os": "Linux",
            "success": False,
            "error": "No auth log accessible. Run agent as root or check log paths.",
        }

    failed_by_user: Counter = Counter()
    failed_by_ip: Counter = Counter()
    accepted: list[dict] = []
    sudo_commands: list[dict] = []
    invalid_users: Counter = Counter()
    other_events: list[str] = []

    for line in lines:
        for name, pat in _PATTERNS.items():
            m = pat.search(line)
            if not m:
                continue
            if name == "failed_password":
                user, ip = m.group(1), m.group(2)
                failed_by_user[user] += 1
                failed_by_ip[ip] += 1
            elif name in ("accepted_password", "accepted_publickey"):
                accepted.append({"user": m.group(1), "from": m.group(2),
                                 "method": name.replace("accepted_", "")})
            elif name == "sudo_command":
                sudo_commands.append({"user": m.group(1), "command": m.group(2)[:200]})
            elif name == "ssh_invalid_user":
                invalid_users[m.group(1)] += 1
            elif name in ("new_user", "password_change"):
                other_events.append(line.strip()[:300])
            break

    # Highlight potential brute-force IPs (>= 5 failed attempts)
    bruteforce_ips = {ip: count for ip, count in failed_by_ip.items() if count >= 5}

    return {
        "os": "Linux",
        "success": True,
        "lines_analyzed": len(lines),
        "failed_logins": {
            "total": sum(failed_by_user.values()),
            "by_user": dict(failed_by_user.most_common(10)),
            "by_source_ip": dict(failed_by_ip.most_common(10)),
            "potential_bruteforce_ips": bruteforce_ips,
        },
        "successful_logins": accepted[-15:],  # last 15
        "sudo_invocations": sudo_commands[-20:],
        "invalid_user_attempts": dict(invalid_users.most_common(10)),
        "user_management_events": other_events[-10:],
    }


# ---------- Windows ----------

_WINDOWS_EVENTS_OF_INTEREST = {
    "4624": "successful logon",
    "4625": "failed logon",
    "4634": "logoff",
    "4720": "user account created",
    "4724": "password reset",
    "4732": "added to security group",
    "4688": "process creation",
    "4672": "special privileges assigned",
}


def _analyze_windows() -> dict:
    """Query Windows Security log via wevtutil."""
    try:
        # Get last 200 Security events as XML, then heuristically count event IDs
        r = subprocess.run(
            ["wevtutil", "qe", "Security", "/c:200", "/f:text", "/rd:true"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return {
                "os": "Windows", "success": False,
                "error": f"wevtutil failed (need admin): {r.stderr[:300]}",
            }
        text = r.stdout
    except FileNotFoundError:
        return {"os": "Windows", "success": False, "error": "wevtutil not found"}
    except subprocess.TimeoutExpired:
        return {"os": "Windows", "success": False, "error": "wevtutil timed out"}
    except Exception as e:
        return {"os": "Windows", "success": False, "error": str(e)}

    event_counts: Counter = Counter()
    notable_lines: defaultdict[str, list[str]] = defaultdict(list)

    current_event: list[str] = []
    for line in text.splitlines():
        current_event.append(line)
        if "Event ID:" in line:
            try:
                eid = line.split("Event ID:")[1].strip().split()[0]
                event_counts[eid] += 1
                if eid in _WINDOWS_EVENTS_OF_INTEREST and len(notable_lines[eid]) < 5:
                    # Keep the surrounding context (last ~10 lines)
                    notable_lines[eid].append("\n".join(current_event[-15:]))
            except Exception:
                pass
        if line.strip() == "":
            current_event = []

    summary = {}
    for eid, count in event_counts.most_common():
        label = _WINDOWS_EVENTS_OF_INTEREST.get(eid, "other")
        summary[f"{eid} ({label})"] = count

    return {
        "os": "Windows",
        "success": True,
        "events_analyzed": sum(event_counts.values()),
        "event_id_summary": summary,
        "notable_events_by_id": {
            f"{eid} ({_WINDOWS_EVENTS_OF_INTEREST.get(eid, '?')})": lines[:3]
            for eid, lines in notable_lines.items()
        },
    }


# ---------- Entry ----------

def run(params: dict) -> dict:
    sys = platform.system()
    if sys == "Linux":
        return _analyze_linux()
    if sys == "Windows":
        return _analyze_windows()
    return {"os": sys, "success": False, "error": "Unsupported OS"}
