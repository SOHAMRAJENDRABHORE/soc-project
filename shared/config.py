"""
Central configuration. Loads .env once and exposes settings to all bots.

Every other module imports `settings` from here instead of reading os.environ
directly. Makes it easy to swap config sources (env, vault, etc.) later.
"""
from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class Settings:
    # ---- LLM (Azure OpenAI) ----
    AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    AZURE_OPENAI_KEY: str = os.getenv("AZURE_OPENAI_KEY", "")
    AZURE_OPENAI_DEPLOYMENT: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-mini")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

    # ---- Threat intel ----
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    # URLhaus, ThreatFox, MalwareBazaar need no keys (abuse.ch public APIs)

    # ---- Behavior ----
    ENRICHMENT_TIMEOUT_SECONDS: int = _int("ENRICHMENT_TIMEOUT_SECONDS", 15)
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ---- Central server ----
    CENTRAL_SERVER_HOST: str = os.getenv("CENTRAL_SERVER_HOST", "0.0.0.0")
    CENTRAL_SERVER_PORT: int = _int("CENTRAL_SERVER_PORT", 8080)
    AGENT_AUTH_TOKEN: str = os.getenv("AGENT_AUTH_TOKEN", "")
    JOB_EXPIRY_SECONDS: int = _int("JOB_EXPIRY_SECONDS", 600)
    AGENT_OFFLINE_AFTER_SECONDS: int = _int("AGENT_OFFLINE_AFTER_SECONDS", 60)
    CENTRAL_DB_PATH: str = os.getenv("CENTRAL_DB_PATH", "central_server.db")

    # ---- Endpoint agent ----
    CENTRAL_SERVER_URL: str = os.getenv("CENTRAL_SERVER_URL", "http://127.0.0.1:8080")
    AGENT_POLL_INTERVAL: int = _int("AGENT_POLL_INTERVAL", 5)
    AGENT_ID: str = os.getenv("AGENT_ID", "")

    # ---- Forensic tool paths (on the agent machine) ----
    VOLATILITY_BINARY: str = os.getenv("VOLATILITY_BINARY", "vol")
    GHIDRA_HEADLESS: str = os.getenv("GHIDRA_HEADLESS", "")
    SAMPLE_MEMORY_DUMP: str = os.getenv("SAMPLE_MEMORY_DUMP", "")
    SAMPLE_BINARY: str = os.getenv("SAMPLE_BINARY", "")

    # ---- Onboarding Agent ----
    ONBOARDING_ENCRYPTION_KEY: str = os.getenv("ONBOARDING_ENCRYPTION_KEY", "")
    ONBOARDING_POLL_INTERVAL: int = _int("ONBOARDING_POLL_INTERVAL", 30)
    # Where mock alert JSON files live, relative to project root
    ONBOARDING_SAMPLE_DIR: str = os.getenv(
        "ONBOARDING_SAMPLE_DIR", "onboarding_agent/sample_alerts"
    )

    def missing_required_keys(self) -> list[str]:
        missing = []
        if not self.AZURE_OPENAI_KEY:
            missing.append("AZURE_OPENAI_KEY")
        if not self.AZURE_OPENAI_ENDPOINT:
            missing.append("AZURE_OPENAI_ENDPOINT")
        return missing

    def enricher_status(self) -> dict[str, bool]:
        return {
            "virustotal": bool(self.VIRUSTOTAL_API_KEY),
            "abuseipdb": bool(self.ABUSEIPDB_API_KEY),
            "otx": bool(self.OTX_API_KEY),
            "urlhaus": True,                       # public
            "threatfox": True,                     # public
            "malwarebazaar": True,                 # public
            "greynoise": bool(self.GREYNOISE_API_KEY),
            "shodan": bool(self.SHODAN_API_KEY),
        }

    # ---- VIP gating (Action Bot) ----
    # Comma-separated list of users/hosts/endpoint_ids considered VIP.
    # When the target endpoint maps to a VIP, Action Bot requires explicit approval
    # even in auto/single-workflow mode.
    VIP_USERS: str = os.getenv("VIP_USERS", "")  # e.g. "ceo,cfo,alice@example.com"

    def vip_list(self) -> set[str]:
        return {x.strip().lower() for x in self.VIP_USERS.split(",") if x.strip()}

    def is_vip(self, identifier: str | None) -> bool:
        if not identifier:
            return False
        ident = identifier.lower()
        vips = self.vip_list()
        # Match exact, or substring (so "alice" matches "alice@corp.com" or "WIN-ALICE-LAPTOP")
        return any(v == ident or v in ident for v in vips)


settings = Settings()
