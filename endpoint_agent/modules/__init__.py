"""
Forensic modules + reversible action handlers.

Each module exposes a `run(params: dict) -> dict` function.
Adding a new one: write the file, register it in REGISTRY below.
"""
from __future__ import annotations

from typing import Callable

from . import (
    processes, network, persistence, file_inspect,
    memory, binary_re,
    yara_scan, deep_memory, auth_logs,         # deeper forensics
    actions,                                    # remediation
)

# Action name → handler function
REGISTRY: dict[str, Callable[[dict], dict]] = {
    # Forensic collection
    "processes": processes.run,
    "network": network.run,
    "persistence": persistence.run,
    "file_inspect": file_inspect.run,
    "memory_dump": memory.run,
    "binary_re": binary_re.run,
    "yara_scan": yara_scan.run,
    "deep_memory": deep_memory.run,
    "auth_logs": auth_logs.run,

    # Remediation (reversible, evidence-preserving)
    "isolate_endpoint": actions.make_runner(actions.isolate_endpoint),
    "unisolate_endpoint": actions.make_runner(actions.unisolate_endpoint),
    "block_ip": actions.make_runner(actions.block_ip),
    "unblock_ip": actions.make_runner(actions.unblock_ip),
    "block_domain": actions.make_runner(actions.block_domain),
    "quarantine_file": actions.make_runner(actions.quarantine_file),
    "disable_user": actions.make_runner(actions.disable_user),
    "snapshot_process": actions.make_runner(actions.snapshot_process),
}


def available_actions() -> list[str]:
    return sorted(REGISTRY.keys())
