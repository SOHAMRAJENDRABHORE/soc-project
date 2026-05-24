"""AlienVault OTX enricher. Supports IPs, domains, URLs, hashes."""
from __future__ import annotations

import httpx
from shared.config import settings
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class OTXEnricher(BaseEnricher):
    name = "otx"
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def supported_types(self) -> set[IOCType]:
        return {
            IOCType.IP, IOCType.DOMAIN, IOCType.URL,
            IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256,
        }

    @property
    def configured(self) -> bool:
        return bool(settings.OTX_API_KEY)

    def _section(self, ioc: IOC) -> str:
        if ioc.type == IOCType.IP:
            return f"IPv4/{ioc.value}/general"
        if ioc.type == IOCType.DOMAIN:
            return f"domain/{ioc.value}/general"
        if ioc.type == IOCType.URL:
            return f"url/{ioc.value}/general"
        if ioc.type in {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}:
            return f"file/{ioc.value}/general"
        return ""

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        if not self.configured:
            return self._failed(ioc, "OTX API key not configured")

        section = self._section(ioc)
        if not section:
            return self._failed(ioc, f"Unsupported IOC type {ioc.type}")

        try:
            r = await client.get(
                f"{self.BASE_URL}/{section}",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
                timeout=self.timeout,
            )
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}: {r.text[:200]}")

            data = r.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])

            # Collect threat tags from pulses
            tags: list[str] = []
            for p in pulses[:5]:  # cap to avoid noise
                tags.extend(p.get("tags", []) or [])
                if p.get("name"):
                    tags.append(p["name"])
            tags = list({t for t in tags if t})[:15]

            # Score: OTX doesn't give a direct score; we derive one from pulse count
            if pulse_count >= 5:
                score = 80.0
                reputation = "malicious"
            elif pulse_count >= 1:
                score = 50.0
                reputation = "suspicious"
            else:
                score = 0.0
                reputation = "clean"

            return EnrichmentResult(
                source=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                success=True,
                malicious_score=score,
                reputation=reputation,
                tags=tags,
                summary=f"{pulse_count} OTX pulses",
                raw_response={"pulse_count": pulse_count, "tags": tags},
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network error: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
