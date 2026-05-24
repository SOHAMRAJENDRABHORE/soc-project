"""
YARA rule scanning. Scans a file (or set of files) against a directory of YARA rules.

Setup:
  pip install yara-python    (already in requirements.txt)

Rules:
  By default looks in ~/agentic-soc/yara_rules/*.yar
  Override with YARA_RULES_DIR env var.

  For demo, download a free rule pack:
    git clone https://github.com/Yara-Rules/rules.git yara_rules
  or grab a single .yar file (we ship one inline below if no rules are present).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from shared.config import settings, PROJECT_ROOT
from shared.logger import get_logger

log = get_logger(__name__)


# Built-in sample rule used if no rules dir is configured.
# Realistic patterns matching the fake_malware.elf demo binary's strings.
_DEMO_RULE = r"""
rule AgenticSOC_Demo_C2_Indicator {
    meta:
        description = "Demo: hard-coded C2 URLs"
        author = "AgenticSOC project"
        severity = "high"
    strings:
        $a = "evil-domain"
        $b = "/beacon"
        $c = ".onion"
    condition:
        any of them
}

rule AgenticSOC_Demo_Ransomware_Behavior {
    meta:
        description = "Demo: ransomware command patterns"
        severity = "critical"
    strings:
        $a = "vssadmin.exe delete shadows" ascii wide nocase
        $b = "bcdedit" ascii wide nocase
        $c = "wbadmin delete" ascii wide nocase
        $d = "ENCRYPTED" ascii wide
        $e = "BTC" ascii wide
    condition:
        2 of them
}

rule AgenticSOC_Demo_Process_Injection {
    meta:
        description = "Demo: process injection API chain"
        severity = "high"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}
"""


def _rules_dir() -> Path:
    cfg = os.getenv("YARA_RULES_DIR", "")
    if cfg:
        return Path(cfg).expanduser()
    return PROJECT_ROOT / "yara_rules"


def _collect_targets(params: dict) -> list[Path]:
    """Resolve the list of files to scan."""
    paths = params.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    # Fall back to SAMPLE_BINARY if no explicit target
    if not paths and settings.SAMPLE_BINARY:
        paths = [settings.SAMPLE_BINARY]
    return [Path(p) for p in paths if p]


def _load_rules() -> tuple[Any, str]:
    """Compile rules from disk, or use built-in demo rule if none exist."""
    try:
        import yara
    except ImportError:
        return None, "yara-python not installed (pip install yara-python)"

    rules_dir = _rules_dir()
    rule_files = []
    if rules_dir.exists() and rules_dir.is_dir():
        rule_files = list(rules_dir.glob("**/*.yar")) + list(rules_dir.glob("**/*.yara"))

    if rule_files:
        try:
            filepaths = {p.stem: str(p) for p in rule_files}
            compiled = yara.compile(filepaths=filepaths)
            return compiled, f"compiled {len(rule_files)} rule files from {rules_dir}"
        except yara.SyntaxError as e:
            log.warning(f"YARA rule syntax error: {e} — falling back to demo rules")

    # Fallback to inline demo rules
    try:
        compiled = yara.compile(source=_DEMO_RULE)
        return compiled, "using built-in demo rules (no rules dir found)"
    except Exception as e:
        return None, f"could not compile demo rules: {e}"


def run(params: dict) -> dict:
    """
    params:
      paths: list[str] of files to scan (or string for single file)
      max_match_strings: int, limit strings per match (default 10)
    """
    targets = _collect_targets(params)
    if not targets:
        return {"success": False, "error": "No target files. Set SAMPLE_BINARY or pass paths."}

    rules, rules_info = _load_rules()
    if rules is None:
        return {"success": False, "error": rules_info, "scanned": []}

    max_strings = int(params.get("max_match_strings", 10))
    results = []
    for target in targets:
        if not target.exists():
            results.append({"file": str(target), "exists": False, "matches": []})
            continue
        try:
            file_matches = rules.match(str(target), timeout=60)
            match_dicts = []
            for m in file_matches:
                strings_list = []
                # yara-python's match.strings is a list of Match objects in 4.x+
                # Each has identifier and instances. Older API: tuples.
                try:
                    for s in (m.strings or [])[:max_strings]:
                        # Newer API
                        if hasattr(s, "identifier"):
                            insts = []
                            for inst in (getattr(s, "instances", None) or [])[:3]:
                                insts.append({
                                    "offset": getattr(inst, "offset", None),
                                    "matched": (
                                        inst.matched_data.decode("utf-8", "replace")[:200]
                                        if getattr(inst, "matched_data", None) else ""
                                    ),
                                })
                            strings_list.append({"name": s.identifier, "instances": insts})
                        else:
                            # Older API: (offset, identifier, matched_bytes)
                            offset, ident, mb = s
                            strings_list.append({
                                "name": ident,
                                "instances": [{"offset": offset,
                                               "matched": mb.decode("utf-8", "replace")[:200]}],
                            })
                except Exception as e:
                    log.warning(f"YARA string extraction issue: {e}")
                match_dicts.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags or []),
                    "meta": dict(m.meta or {}),
                    "strings": strings_list,
                })
            results.append({
                "file": str(target),
                "exists": True,
                "match_count": len(file_matches),
                "matches": match_dicts,
            })
        except Exception as e:
            results.append({"file": str(target), "exists": True, "error": str(e), "matches": []})

    total_matches = sum(r.get("match_count", 0) for r in results)
    return {
        "success": True,
        "rules_info": rules_info,
        "files_scanned": len(targets),
        "total_matches": total_matches,
        "scanned": results,
    }
