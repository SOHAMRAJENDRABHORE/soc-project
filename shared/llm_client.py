"""
Single point of contact with the LLM. Every bot uses this.

Designed so swapping providers means changing ONLY this file.
The public API (LLMClient.generate_json / generate_text) stays the same.
"""
from __future__ import annotations

import json
from typing import Any

from openai import AzureOpenAI

from .config import settings
from .logger import get_logger

log = get_logger(__name__)


class LLMClient:
    """Thin wrapper over Azure OpenAI. Returns parsed JSON when asked."""

    def __init__(self, model_name: str | None = None):
        if not settings.AZURE_OPENAI_KEY:
            raise RuntimeError(
                "AZURE_OPENAI_KEY not set. Add your Azure OpenAI key to .env."
            )
        if not settings.AZURE_OPENAI_ENDPOINT:
            raise RuntimeError(
                "AZURE_OPENAI_ENDPOINT not set. Add your Azure OpenAI endpoint to .env."
            )
        self.deployment = model_name or settings.AZURE_OPENAI_DEPLOYMENT
        self.model_name = self.deployment  # alias used by verdict_engine / synthesis
        self._client = AzureOpenAI(
            azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
            api_key=settings.AZURE_OPENAI_KEY,
            api_version=settings.AZURE_OPENAI_API_VERSION,
        )
        log.info(f"LLM client initialized — deployment={self.deployment}")

    def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Ask the LLM for JSON output. Returns parsed dict."""
        text: str = ""
        try:
            response = self._client.chat.completions.create(
                model=self.deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            text = (response.choices[0].message.content or "").strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            log.error(f"LLM returned invalid JSON: {e}. Raw: {text[:500]}")
            raise
        except Exception as e:
            log.error(f"LLM call failed: {e}")
            raise

    def generate_text(self, system_prompt: str = "", prompt: str = "") -> str:
        """For cases where we want free-form text, not JSON."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt or system_prompt})
        response = self._client.chat.completions.create(
            model=self.deployment,
            messages=messages,
            temperature=0.3,
        )
        return response.choices[0].message.content or ""
