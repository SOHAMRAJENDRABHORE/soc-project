"""VirusTotal v3 API enricher. Supports hashes, IPs, domains, URLs."""
from __future__ import annotations

import base64
import httpx
from shared.config import settings
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class VirusTotalEnricher(BaseEnricher):
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def supported_types(self) -> set[IOCType]:
        return {
            IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256,
            IOCType.IP, IOCType.DOMAIN, IOCType.URL,
        }

    @property
    def configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY)

    def _endpoint(self, ioc: IOC) -> str:
        if ioc.type in {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}:
            return f"/files/{ioc.value}"
        if ioc.type == IOCType.IP:
            return f"/ip_addresses/{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"/domains/{ioc.value}"
        if ioc.type == IOCType.URL:
            # VT requires URL-safe base64 of the URL
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            return f"/urls/{url_id}"
        return ""

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        if not self.configured:
            return self._failed(ioc, "VirusTotal API key not configured")

        endpoint = self._endpoint(ioc)
        if not endpoint:
            return self._failed(ioc, f"Unsupported IOC type {ioc.type}")

        try:
            r = await client.get(
                f"{self.BASE_URL}{endpoint}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=self.timeout,
            )
            if r.status_code == 404:
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="unknown",
                    summary="Not seen by VirusTotal", malicious_score=0.0,
                )
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}: {r.text[:200]}")

            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = max(1, malicious + suspicious + harmless + undetected)

            score = ((malicious + 0.5 * suspicious) / total) * 100

            if malicious >= 3:
                reputation = "malicious"
            elif malicious + suspicious >= 1:
                reputation = "suspicious"
            else:
                reputation = "clean"

            tags = []
            if attrs.get("popular_threat_classification"):
                tags.extend(attrs["popular_threat_classification"].get("suggested_threat_label", "").split("."))
            tags = [t for t in tags if t]

            return EnrichmentResult(
                source=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                success=True,
                malicious_score=round(score, 1),
                reputation=reputation,
                tags=tags,
                summary=f"{malicious} malicious / {total} engines",
                raw_response={"stats": stats, "tags": tags},
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network error: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
