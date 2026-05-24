"""
Runs all configured enrichers against all IOCs concurrently.

This is where the 7-source parallel enrichment from your original arch lives.
Right now we have 3 enrichers (VT, AbuseIPDB, OTX); adding more is one file.
"""
from __future__ import annotations

import asyncio
import httpx
from shared.schemas import IOC, EnrichmentResult
from shared.config import settings
from shared.logger import get_logger

from .base import BaseEnricher
from .virustotal import VirusTotalEnricher
from .abuseipdb import AbuseIPDBEnricher
from .otx import OTXEnricher
from .urlhaus import URLhausEnricher
from .threatfox import ThreatFoxEnricher
from .greynoise import GreyNoiseEnricher
from .shodan import ShodanEnricher
from .malwarebazaar import MalwareBazaarEnricher

log = get_logger(__name__)


def get_enrichers() -> list[BaseEnricher]:
    """Return all enricher instances. Add new ones here."""
    t = settings.ENRICHMENT_TIMEOUT_SECONDS
    return [
        VirusTotalEnricher(timeout=t),
        AbuseIPDBEnricher(timeout=t),
        OTXEnricher(timeout=t),
        URLhausEnricher(timeout=t),
        ThreatFoxEnricher(timeout=t),
        GreyNoiseEnricher(timeout=t),
        ShodanEnricher(timeout=t),
        MalwareBazaarEnricher(timeout=t),
    ]


async def _enrich_all_async(iocs: list[IOC]) -> list[EnrichmentResult]:
    enrichers = [e for e in get_enrichers() if e.configured]
    if not enrichers:
        log.warning("No enrichers configured. Add API keys in .env.")
        return []

    # Build (enricher, ioc) pairs for everything supported
    tasks_meta: list[tuple[BaseEnricher, IOC]] = []
    for ioc in iocs:
        for enr in enrichers:
            if enr.supports(ioc):
                tasks_meta.append((enr, ioc))

    if not tasks_meta:
        log.info("No IOCs supported by any enricher.")
        return []

    log.info(f"Running {len(tasks_meta)} enrichment calls in parallel "
             f"({len(enrichers)} sources × {len(iocs)} IOCs)")

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[enr.enrich(client, ioc) for enr, ioc in tasks_meta],
            return_exceptions=True,
        )

    out: list[EnrichmentResult] = []
    for (enr, ioc), res in zip(tasks_meta, results):
        if isinstance(res, Exception):
            out.append(EnrichmentResult(
                source=enr.name, ioc_value=ioc.value, ioc_type=ioc.type,
                success=False, error=str(res),
            ))
        else:
            out.append(res)
    return out


def enrich_all(iocs: list[IOC]) -> list[EnrichmentResult]:
    """Sync wrapper for the async orchestrator."""
    return asyncio.run(_enrich_all_async(iocs))
