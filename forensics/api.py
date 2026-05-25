"""
Forensics Lab API — standalone endpoints for YARA, Ghidra, Volatility,
and direct IOC enrichment lookups.

Mounted at /forensics by the central server.
All heavy operations run in a thread pool so they don't block the event loop.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from shared.logger import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/forensics", tags=["forensics"])


# ── Request models ────────────────────────────────────────────────────────────

class YaraScanRequest(BaseModel):
    paths: list[str] = []                   # files to scan; falls back to SAMPLE_BINARY


class GhidraRequest(BaseModel):
    binary_path: str = ""                   # falls back to SAMPLE_BINARY
    timeout_seconds: int = 300


class MemoryRequest(BaseModel):
    dump_path: str = ""                     # falls back to SAMPLE_MEMORY_DUMP
    dump_os: str = "windows"               # "windows" | "linux"
    plugins: list[str] = []                # empty = auto-select defaults
    deep: bool = False                     # True = run deep_memory plugins too


class IOCLookupRequest(BaseModel):
    value: str                             # the IOC value to look up
    ioc_type: Optional[str] = None        # "ip","domain","url","hash_md5","hash_sha256","hash_sha1","email" — or None to auto-detect


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_ioc_type(value: str) -> str:
    """Best-effort IOC type detection from the raw value."""
    v = value.strip()
    if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "hash_sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "hash_sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "hash_md5"
    if re.match(r"https?://", v, re.IGNORECASE):
        return "url"
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", v):
        return "email"
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", v):
        return "domain"
    return "unknown"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/yara")
async def yara_scan(req: YaraScanRequest):
    """Run YARA rules against one or more file paths."""
    from endpoint_agent.modules import yara_scan as ys
    result = await asyncio.to_thread(ys.run, {"paths": req.paths})
    return result


@router.post("/ghidra")
async def ghidra_analysis(req: GhidraRequest):
    """Run Ghidra headless analysis (or strings fallback) on a binary."""
    from endpoint_agent.modules import binary_re
    result = await asyncio.to_thread(binary_re.run, {
        "binary_path": req.binary_path,
        "timeout_seconds": req.timeout_seconds,
    })
    return result


@router.post("/memory")
async def memory_analysis(req: MemoryRequest):
    """Run Volatility plugins against a memory dump."""
    if req.deep:
        from endpoint_agent.modules import deep_memory
        result = await asyncio.to_thread(deep_memory.run, {
            "dump_path": req.dump_path,
            "dump_os": req.dump_os,
            "plugins": req.plugins or None,
        })
    else:
        from endpoint_agent.modules import memory
        result = await asyncio.to_thread(memory.run, {
            "dump_path": req.dump_path,
            "dump_os": req.dump_os,
            "plugins": req.plugins or None,
        })
    return result


@router.post("/ioc")
async def ioc_lookup(req: IOCLookupRequest):
    """
    Enrich a single IOC through all configured threat intel sources.
    Supports: IP, domain, URL, MD5, SHA1, SHA256, email.
    """
    from shared.schemas import IOC, IOCType
    from decision_bot.enrichment.orchestrator import _enrich_all_async

    value = req.value.strip()
    if not value:
        return {"success": False, "error": "No IOC value provided"}

    raw_type = req.ioc_type or _detect_ioc_type(value)

    # Map to IOCType enum
    type_map = {
        "ip": IOCType.IP,
        "domain": IOCType.DOMAIN,
        "url": IOCType.URL,
        "hash_md5": IOCType.HASH_MD5,
        "hash_sha1": IOCType.HASH_SHA1,
        "hash_sha256": IOCType.HASH_SHA256,
        "email": IOCType.EMAIL,
    }
    ioc_type_enum = type_map.get(raw_type, IOCType.DOMAIN)

    ioc = IOC(type=ioc_type_enum, value=value)
    log.info(f"[Forensics/IOC] Enriching {raw_type}: {value}")

    results = await _enrich_all_async([ioc])

    enriched = [r.model_dump() for r in results]
    successful = [r for r in enriched if r.get("success")]
    max_score = max((r.get("malicious_score") or 0 for r in successful), default=0)

    return {
        "success": True,
        "ioc_value": value,
        "ioc_type": raw_type,
        "enrichment": enriched,
        "sources_queried": len(results),
        "sources_hit": len(successful),
        "max_malicious_score": max_score,
        "verdict": (
            "malicious" if max_score >= 75 else
            "suspicious" if max_score >= 40 else
            "clean" if successful else "unknown"
        ),
    }
