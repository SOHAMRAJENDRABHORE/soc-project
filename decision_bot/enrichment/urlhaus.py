"""URLhaus by abuse.ch. Lookups for URLs, domains, hashes. NO API KEY NEEDED."""
from __future__ import annotations

import httpx
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class URLhausEnricher(BaseEnricher):
    name = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def supported_types(self) -> set[IOCType]:
        return {
            IOCType.URL, IOCType.DOMAIN,
            IOCType.HASH_MD5, IOCType.HASH_SHA256,
        }

    @property
    def configured(self) -> bool:
        return True  # public API, no auth

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        try:
            if ioc.type == IOCType.URL:
                endpoint = "/url/"
                form = {"url": ioc.value}
            elif ioc.type == IOCType.DOMAIN:
                endpoint = "/host/"
                form = {"host": ioc.value}
            elif ioc.type in {IOCType.HASH_MD5, IOCType.HASH_SHA256}:
                # URLhaus accepts md5_hash or sha256_hash form field
                endpoint = "/payload/"
                key = "md5_hash" if ioc.type == IOCType.HASH_MD5 else "sha256_hash"
                form = {key: ioc.value}
            else:
                return self._failed(ioc, f"Unsupported type {ioc.type}")

            r = await client.post(f"{self.BASE_URL}{endpoint}", data=form, timeout=self.timeout)
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}")
            data = r.json()
            query_status = data.get("query_status", "unknown")

            if query_status == "no_results":
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="clean", malicious_score=0.0,
                    summary="Not in URLhaus database",
                )
            if query_status not in ("ok",):
                return self._failed(ioc, f"URLhaus query_status: {query_status}")

            # 'ok' means it's KNOWN to URLhaus — meaning it's flagged.
            threat = data.get("threat") or data.get("payload_type") or "malicious"
            tags = data.get("tags") or []
            url_count = data.get("url_count") or 0
            summary = f"Known to URLhaus · threat={threat}"
            if url_count:
                summary += f" · {url_count} URLs"

            return EnrichmentResult(
                source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                success=True,
                malicious_score=85.0,
                reputation="malicious",
                tags=tags[:10] if isinstance(tags, list) else [],
                summary=summary,
                raw_response={"threat": threat, "url_count": url_count, "tags": tags},
            )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
