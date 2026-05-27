"""
Seed the database with demo tenants so the onboarding agent has something to poll.

Run this ONCE on any new machine after starting the central server:
    python seed_demo_tenants.py

Creates two mock tenants (Acme Corp and Globex Inc) that feed from the
sample alert JSON files in onboarding_agent/sample_alerts/.
Safe to run multiple times — skips tenants that already exist.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make sure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from central_server import db
from shared.config import settings
from shared.logger import get_logger

log = get_logger("seed")

DEMO_TENANTS = [
    {
        "tenant_id":    "acme-corp",
        "display_name": "Acme Corp (Demo)",
        "provider_type": "mock",
        "provider_config": {
            "alert_file":      "acme_corp.json",
            "alerts_per_poll": 2,
            "loop":            True,
        },
        "ingestion_mode": "auto",
        "enabled":        True,
        "credentials":    {},
    },
    {
        "tenant_id":    "globex-inc",
        "display_name": "Globex Inc (Demo)",
        "provider_type": "mock",
        "provider_config": {
            "alert_file":      "globex_inc.json",
            "alerts_per_poll": 1,
            "loop":            True,
        },
        "ingestion_mode": "auto",
        "enabled":        True,
        "credentials":    {},
    },
]


def main():
    if not settings.ONBOARDING_ENCRYPTION_KEY:
        print("[ERROR] ONBOARDING_ENCRYPTION_KEY not set in .env")
        print("        Copy your .env file to this machine first.")
        print("        Or generate a new key:")
        print('        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
        sys.exit(1)

    db.init_db()

    existing = {t["tenant_id"] for t in db.list_tenants()}
    created = 0

    for t in DEMO_TENANTS:
        if t["tenant_id"] in existing:
            print(f"  skip  {t['tenant_id']} — already exists")
            continue

        # encrypt_credentials expects a dict, stores it encrypted
        from onboarding_agent.tenant_manager import upsert_tenant_with_credentials
        upsert_tenant_with_credentials(
            tenant_id=t["tenant_id"],
            display_name=t["display_name"],
            provider_type=t["provider_type"],
            provider_config=t["provider_config"],
            ingestion_mode=t["ingestion_mode"],
            enabled=t["enabled"],
            credentials=t["credentials"],
        )
        print(f"  created {t['tenant_id']} ({t['display_name']})")
        created += 1

    print()
    if created:
        print(f"Done — {created} tenant(s) created.")
        print("Now run the onboarding agent:")
        print("    python -m onboarding_agent.bot")
    else:
        print("All demo tenants already exist — nothing to do.")


if __name__ == "__main__":
    main()
