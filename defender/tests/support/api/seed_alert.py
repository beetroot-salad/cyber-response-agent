"""Dev only: store one alert for a tenant so the real API server has something to list and investigate (#1083 N9).

No product command creates alerts (intake is its own issue); this script writes one through the job store the
way intake will. Usage, with `DEFENDER_DATABASE_DSN` set:

    python -m defender.tests.support.api.seed_alert <tenant-id> <vendor-ticket-id> [<alert.json>]

Without a file it stores a minimal alert whose timestamp is now. The tenant's alert mapping (saved through the API
or `tenant.py set-alert-mapping`) derives the alert's title and description from the JSON at this moment."""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
from pathlib import Path

from defender.jobs.store import JobStore
from defender.records.formats import TenantId


async def _seed(dsn: str, tenant: str, ticket: str, raw: bytes, now: dt.datetime) -> None:
    store = JobStore(dsn, clock=lambda: dt.datetime.now(dt.UTC))
    try:
        stored = await store.insert_alert(TenantId(tenant), vendor="dev-seed", vendor_ticket_id=ticket, fired_at=now,
                                          changed_at=now, received_at=now, raw=raw)
    finally:
        await store.close()
    print(f"alert {stored.alert_id}")


def main() -> int:
    from defender._log import configure_from_env

    configure_from_env()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tenant")
    parser.add_argument("ticket")
    parser.add_argument("alert_file", nargs="?")
    args = parser.parse_args()
    now = dt.datetime.now(dt.UTC)
    raw = (Path(args.alert_file).read_bytes() if args.alert_file else
           json.dumps({"rule": {"id": "dev-seed", "description": "A seeded dev alert"},
                       "alert_timestamp": now.isoformat()}).encode() + b"\n")
    asyncio.run(_seed(os.environ["DEFENDER_DATABASE_DSN"], args.tenant, args.ticket, raw, now))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
