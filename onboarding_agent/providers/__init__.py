"""
Provider registry. Adding a new provider:
  1. Implement `MyProvider(AlertProvider)` in a new file
  2. Add it to PROVIDERS below
  3. Add the enum value to shared.schemas.ProviderType
"""
from __future__ import annotations

from typing import Type
from .base import AlertProvider
from .mock import MockProvider
from .webhook import WebhookProvider

# provider_type identifier → class
PROVIDERS: dict[str, Type[AlertProvider]] = {
    "mock": MockProvider,
    "webhook": WebhookProvider,
    # "graph": GraphProvider,   # not yet implemented — needs M365 dev tenant
}


def get_provider_class(provider_type: str) -> Type[AlertProvider] | None:
    return PROVIDERS.get(provider_type)


def supported_provider_types() -> list[str]:
    return sorted(PROVIDERS.keys())
