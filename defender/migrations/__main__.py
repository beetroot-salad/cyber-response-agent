"""The dev command: `python -m defender.migrations upgrade`, on the database named by
`DEFENDER_DATABASE_DSN`."""

from __future__ import annotations

import argparse
import os
import sys

from defender._log import configure_from_env
from defender.migrations import upgrade

DSN_ENV = "DEFENDER_DATABASE_DSN"


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m defender.migrations")
    parser.add_argument("command", choices=["upgrade"])
    parser.parse_args()
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        print(f"{DSN_ENV} is not set; it names the database to migrate", file=sys.stderr)
        return 2
    upgrade(dsn)
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
