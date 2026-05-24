"""
GreyNoise. Identifies internet noise vs. targeted activity. Free tier requires key.
Get one at: https://viz.greynoise.io/account/api-key
"""
from __future__ import annotations

import httpx
from shared.config import settings
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class GreyNoiseEnricher(BaseEnricher):
    name = "greynoise"
    URL = "https://api.greynoise.io/v3/community/"

    def supported_types(self) -> set[IOCType]:
        return {IOCType.IP}

    @property
    def configured(self) -> bool:
        return bool(settings.GREYNOISE_API_KEY)

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        if not self.configured:
            return self._failed(ioc, "GREYNOISE_API_KEY not configured")
        try:
            r = await client.get(
                f"{self.URL}{ioc.value}",
                headers={"key": settings.GREYNOISE_API_KEY, "Accept": "application/json"},
                timeout=self.timeout,
            )
            if r.status_code == 404:
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="unknown", malicious_score=0.0,
                    summary="IP not seen by GreyNoise",
                )
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}")

            data = r.json()
            classification = data.get("classification", "unknown")
            noise = data.get("noise", False)
            riot = data.get("riot", False)
            name = data.get("name", "")
            last_seen = data.get("last_seen", "")

            # Classification → reputation mapping
            # malicious / benign / unknown
            if classification == "malicious":
                rep, score = "malicious", 85.0
            elif classification == "benign":
                rep, score = "clean", 0.0
            else:
                rep, score = "suspicious" if noise else "unknown", 30.0 if noise else 0.0

            tags = []
            if noise:
                tags.append("internet-noise-scanner")
            if riot:
                tags.append("common-business-service")
            if name:
                tags.append(name)

            summary_bits = [f"class={classification}"]
            if noise:
                summary_bits.append("scanner")
            if riot:
                summary_bits.append("RIOT")
            if last_seen:
                summary_bits.append(f"last={last_seen}")

            return EnrichmentResult(
                source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                success=True,
                malicious_score=score,
                reputation=rep,
                tags=tags,
                summary=" · ".join(summary_bits),
                raw_response=data,
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
