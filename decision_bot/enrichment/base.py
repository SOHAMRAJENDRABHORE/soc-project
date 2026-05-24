"""
Abstract base for threat intel enrichers.

To add a new source (e.g., Shodan, GreyNoise), subclass BaseEnricher and
implement supports() and enrich(). The orchestrator picks it up automatically.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import httpx
from shared.schemas import IOC, IOCType, EnrichmentResult
from shared.logger import get_logger

log = get_logger(__name__)


class BaseEnricher(ABC):
    """Subclass this to add a new threat intel source."""

    name: str = "base"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    @abstractmethod
    def supported_types(self) -> set[IOCType]:
        """Which IOC types this enricher can handle."""
        ...

    @abstractmethod
    async def enrich(self, client: httpx.AsyncClient, ioc: IOC) -> EnrichmentResult:
        """Query the source for this IOC. Must not raise — return a failed result instead."""
        ...

    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported_types()

    @property
    def configured(self) -> bool:
        """Whether this enricher has credentials. Override if API key needed."""
        return True

    def _failed(self, ioc: IOC, error: str) -> EnrichmentResult:
        return EnrichmentResult(
            source=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            success=False,
            error=error,
        )
