"""Network connection telemetry."""
from __future__ import annotations

import psutil
from ipaddress import ip_address
from shared.logger import get_logger

log = get_logger(__name__)


def _is_external(ip: str) -> bool:
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


def run(params: dict) -> dict:
    """
    Collect active network connections.
    params:
      external_only (bool, default True)
    """
    external_only = params.get("external_only", True)
    conns: list[dict] = []
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return {"error": "Permission denied — agent needs admin/root for net_connections",
                "connections": []}

    for c in raw:
        if not c.raddr:
            continue
        remote_ip = c.raddr.ip
        if external_only and not _is_external(remote_ip):
            continue
        pname = "?"
        try:
            if c.pid:
                pname = psutil.Process(c.pid).name()
        except psutil.Error:
            pass
        conns.append({
            "pid": c.pid,
            "process_name": pname,
            "local": f"{c.laddr.ip}:{c.laddr.port}",
            "remote": f"{c.raddr.ip}:{c.raddr.port}",
            "status": c.status,
        })

    listeners = []
    for c in raw:
        if c.status == "LISTEN":
            listeners.append({
                "pid": c.pid,
                "address": f"{c.laddr.ip}:{c.laddr.port}",
            })

    return {
        "active_connections": conns,
        "listener_count": len(listeners),
        "listeners": listeners[:50],
    }
