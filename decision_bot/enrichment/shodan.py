"""Shodan. IP/device reconnaissance. Free key at https://account.shodan.io/."""
from __future__ import annotations

import httpx
from shared.config import settings
from shared.schemas import IOC, IOCType, EnrichmentResult
from .base import BaseEnricher


class ShodanEnricher(BaseEnricher):
    name = "shodan"

    def supported_types(self) -> set[IOCType]:
        return {IOCType.IP, IOCType.DOMAIN}

    @property
    def configured(self) -> bool:
        return bool(settings.SHODAN_API_KEY)

    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        if not self.configured:
            return self._failed(ioc, "SHODAN_API_KEY not configured")
        try:
            if ioc.type == IOCType.IP:
                url = f"https://api.shodan.io/shodan/host/{ioc.value}"
                params = {"key": settings.SHODAN_API_KEY}
            else:  # domain
                url = f"https://api.shodan.io/dns/domain/{ioc.value}"
                params = {"key": settings.SHODAN_API_KEY}

            r = await client.get(url, params=params, timeout=self.timeout)
            if r.status_code == 404:
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True, reputation="unknown", malicious_score=0.0,
                    summary="Not indexed by Shodan",
                )
            if r.status_code != 200:
                return self._failed(ioc, f"HTTP {r.status_code}")

            data = r.json()

            if ioc.type == IOCType.IP:
                ports = data.get("ports") or []
                org = data.get("org", "")
                country = data.get("country_name", "")
                tags = data.get("tags") or []
                vulns = data.get("vulns") or []
                hostnames = data.get("hostnames") or []

                # Score: open services + vulns
                score = min(80.0, len(ports) * 3 + len(vulns) * 20)
                if vulns:
                    rep = "suspicious" if not any("critical" in v.lower() for v in vulns) else "malicious"
                else:
                    rep = "clean"

                bits = [f"{len(ports)} open ports"]
                if country:
                    bits.append(country)
                if org:
                    bits.append(org)
                if vulns:
                    bits.append(f"{len(vulns)} CVEs")

                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True,
                    malicious_score=score,
                    reputation=rep,
                    tags=list(set((tags or []) + vulns[:3] + hostnames[:2])),
                    summary=" · ".join(bits),
                    raw_response={"ports": ports[:20], "vulns": vulns, "org": org,
                                  "hostnames": hostnames[:5]},
                )
            else:
                # Domain
                sub = data.get("subdomains") or []
                records = data.get("data") or []
                return EnrichmentResult(
                    source=self.name, ioc_value=ioc.value, ioc_type=ioc.type,
                    success=True,
                    malicious_score=0.0,
                    reputation="clean",
                    tags=sub[:10],
                    summary=f"{len(sub)} subdomains · {len(records)} DNS records",
                    raw_response={"subdomain_count": len(sub),
                                  "record_count": len(records)},
                )
        except httpx.HTTPError as e:
            return self._failed(ioc, f"Network: {e}")
        except Exception as e:
            return self._failed(ioc, f"Unexpected: {e}")
