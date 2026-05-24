"""ThreatFox by abuse.ch. IOC threat intel. NO API KEY NEEDED."""
from __future__ import annotations

import httpx
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class ThreatFoxEnricher(BaseEnricher):
    name = "threatfox"
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    def supported_types(self) -> set[IOCType]:
        return {
            IOCType.IP, IOCType.DOMAIN, IOCType.URL,
            IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256,
        }

    @property
    def configured(self) -> bool:
        return True

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        try:
            payload = {"query": "search_ioc", "search_term": ioc.value}
            r = await client.post(self.URL, json=payload, timeout=self.timeout)
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}")
            data = r.json()
            query_status = data.get("query_status", "unknown")

            if query_status == "no_result":
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="clean", malicious_score=0.0,
                    summary="Not in ThreatFox",
                )
            if query_status != "ok":
                return self._failed(ioc, f"ThreatFox query_status: {query_status}")

            results = data.get("data") or []
            if not results:
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="clean", malicious_score=0.0,
                    summary="No IOC entries",
                )

            # Collate malware families / threat tags across all matching entries
            families = set()
            tags = set()
            confidences = []
            for entry in results[:5]:
                if entry.get("malware_printable"):
                    families.add(entry["malware_printable"])
                for t in entry.get("tags") or []:
                    tags.add(t)
                if entry.get("confidence_level") is not None:
                    confidences.append(entry["confidence_level"])

            avg_conf = sum(confidences) / len(confidences) if confidences else 75
            return EnrichmentResult(
                source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                success=True,
                malicious_score=float(avg_conf),
                reputation="malicious" if avg_conf >= 50 else "suspicious",
                tags=sorted(tags)[:10] + sorted(families)[:5],
                summary=f"ThreatFox: {len(results)} entries · families={sorted(families)[:3]}",
                raw_response={
                    "count": len(results),
                    "families": sorted(families),
                    "tags": sorted(tags),
                },
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
