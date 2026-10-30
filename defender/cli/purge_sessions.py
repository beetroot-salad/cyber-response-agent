"""The deployment's scheduled command: `python -m defender.cli.purge_sessions`, on the
database named by `DEFENDER_DATABASE_DSN`. Removes the sessions sign-in already refuses as
expired; needs no sign-in provider, mail or bootstrap file. Refuses a database whose schema is
not at the migrations head (#1349)."""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import os
import sys

from defender._log import configure_from_env
from defender.migrations import check_version

from defender.identity.postgres import PostgresIdentityRepository

DSN_ENV = "DEFENDER_DATABASE_DSN"


async def _purge(dsn: str) -> int:
    repo = PostgresIdentityRepository(dsn, max_connections=1)
    try:
        return await repo.purge_expired_sessions(now=_dt.datetime.now(_dt.UTC))
    finally:
        await repo.close()


def main() -> int:
    argparse.ArgumentParser(prog="python -m defender.cli.purge_sessions", description=__doc__.splitlines()[0]).parse_args()
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        print(f"{DSN_ENV} is not set; it names the database to purge", file=sys.stderr)
        return 2
    check_version(dsn)
    print(f"purged {asyncio.run(_purge(dsn))} expired sessions")
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
