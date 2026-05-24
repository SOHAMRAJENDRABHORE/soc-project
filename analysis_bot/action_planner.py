"""
Pick which forensic actions to run based on the Verdict.

Rule-based (not LLM) — fast, deterministic, no extra API call.
The LLM gets used later for synthesis.

Depth scales with severity:
  - benign / low confidence    → baseline only (processes, network, persistence)
  - suspicious                  → + auth_logs, file_inspect, yara_scan
  - malicious                   → + memory_dump, binary_re
  - critical (high confidence)  → + deep_memory (Volatility extra plugins)
"""
from __future__ import annotations

from shared.schemas import Verdict, VerdictLabel, ForensicAction, IOC, IOCType
from shared.logger import get_logger

log = get_logger(__name__)


# Always run (cheap, no external tools)
BASELINE = ["processes", "network", "persistence"]


def plan_actions(verdict: Verdict) -> list[ForensicAction]:
    actions: list[ForensicAction] = []

    # 1. Always: baseline telemetry
    for name in BASELINE:
        actions.append(ForensicAction(name=name, params={}))

    # 2. Always when suspicious or above: auth logs
    if verdict.label in (VerdictLabel.MALICIOUS, VerdictLabel.SUSPICIOUS):
        actions.append(ForensicAction(name="auth_logs", params={}))

    # 3. File paths in IOCs → inspect them
    file_paths = [i.value for i in verdict.iocs if i.type == IOCType.FILE_PATH]
    if file_paths:
        actions.append(ForensicAction(name="file_inspect", params={"paths": file_paths}))

    # 4. Malicious or suspicious: YARA scan + memory dump
    if verdict.label in (VerdictLabel.MALICIOUS, VerdictLabel.SUSPICIOUS):
        # YARA: scan any binaries mentioned, else fall back to SAMPLE_BINARY
        binaries = [
            p for p in file_paths
            if p.lower().endswith((".exe", ".dll", ".so", ".bin", ".elf"))
            or "." not in p.split("/")[-1].split("\\")[-1]
        ]
        actions.append(ForensicAction(name="yara_scan",
                                      params={"paths": binaries} if binaries else {}))

        # Memory + binary RE
        actions.append(ForensicAction(name="memory_dump", params={}))
        if binaries:
            actions.append(ForensicAction(name="binary_re", params={"binary_path": binaries[0]}))
        else:
            actions.append(ForensicAction(name="binary_re", params={}))

    # 5. Malicious with high confidence → deep memory analysis (slow)
    if verdict.label == VerdictLabel.MALICIOUS and verdict.confidence >= 75:
        actions.append(ForensicAction(name="deep_memory", params={}))

    log.info(f"Planned {len(actions)} actions for verdict "
             f"{verdict.label.value}@{verdict.confidence}%: {[a.name for a in actions]}")
    return actions
