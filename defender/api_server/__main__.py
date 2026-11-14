"""`python -m defender.api_server`: the platform API on PostgreSQL and the real sign-in server, settings from the environment."""

from __future__ import annotations

import os

from . import run

if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    # No transport: each sign-in adapter builds its own connection, honouring the proxy environment (tests pass a fake).
    raise SystemExit(run(os.environ, transport=None))
