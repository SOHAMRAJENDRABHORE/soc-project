"""
Fernet encryption for tenant credentials at rest.

Why this exists:
  Tenant credentials (Graph client_secret, webhook tokens, etc.) get stored
  in the central server's SQLite DB. Plaintext at rest is the most common
  fail mode in real products. Fernet gives us authenticated symmetric
  encryption with one line of code per operation.

How to set up:
  1. Generate a key once:
       python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  2. Paste into .env as ONBOARDING_ENCRYPTION_KEY=<that-value>
  3. Never lose this key. Lose it = lose access to all encrypted credentials.

Production hardening notes (NOT done here):
  - Key should come from a KMS (AWS KMS, GCP KMS, Hashicorp Vault),
    not .env
  - Per-tenant data keys wrapped by a master key (envelope encryption)
  - Key rotation via Fernet's MultiFernet
"""
from __future__ import annotations

import json
from typing import Any
from cryptography.fernet import Fernet, InvalidToken

from .config import settings
from .logger import get_logger

log = get_logger(__name__)


class CredentialCrypto:
    """Encrypt/decrypt JSON-able credential dicts for storage."""

    def __init__(self, key: str | bytes | None = None):
        key = key or settings.ONBOARDING_ENCRYPTION_KEY
        if not key:
            raise RuntimeError(
                "ONBOARDING_ENCRYPTION_KEY not set. Generate one with:\n"
                "  python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            )
        if isinstance(key, str):
            key = key.encode()
        try:
            self._fernet = Fernet(key)
        except Exception as e:
            raise RuntimeError(f"Invalid ONBOARDING_ENCRYPTION_KEY: {e}")

    def encrypt(self, data: dict[str, Any]) -> str:
        """Encrypt a dict to a URL-safe string."""
        plaintext = json.dumps(data, default=str).encode()
        return self._fernet.encrypt(plaintext).decode()

    def decrypt(self, ciphertext: str) -> dict[str, Any]:
        """Decrypt back to a dict. Raises if tampered or wrong key."""
        try:
            plaintext = self._fernet.decrypt(ciphertext.encode())
        except InvalidToken:
            raise RuntimeError(
                "Credential decryption failed — wrong ONBOARDING_ENCRYPTION_KEY "
                "or data was tampered with."
            )
        return json.loads(plaintext.decode())


_singleton: CredentialCrypto | None = None


def get_crypto() -> CredentialCrypto:
    """Lazily instantiate a process-wide CredentialCrypto."""
    global _singleton
    if _singleton is None:
        _singleton = CredentialCrypto()
    return _singleton
