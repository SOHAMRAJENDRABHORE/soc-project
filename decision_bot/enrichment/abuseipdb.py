"""AbuseIPDB enricher. Only IPs."""
from __future__ import annotations

import httpx
from shared.config import settings
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class AbuseIPDBEnricher(BaseEnricher):
    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def supported_types(self) -> set[IOCType]:
        return {IOCType.IP}

    @property
    def configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        if not self.configured:
            return self._failed(ioc, "AbuseIPDB API key not configured")

        try:
            r = await client.get(
                self.BASE_URL,
                params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                headers={
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}: {r.text[:200]}")

            data = r.json().get("data", {})
            confidence = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "??")
            usage = data.get("usageType", "")

            if confidence >= 75:
                reputation = "malicious"
            elif confidence >= 25:
                reputation = "suspicious"
            else:
                reputation = "clean"

            tags = []
            if usage:
                tags.append(usage)
            if data.get("isTor"):
                tags.append("tor")
            if data.get("isPublic") is False:
                tags.append("private")

            return EnrichmentResult(
                source=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                success=True,
                malicious_score=float(confidence),
                reputation=reputation,
                tags=tags,
                summary=f"Abuse score {confidence}% · {reports} reports · {country}",
                raw_response=data,
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network error: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
