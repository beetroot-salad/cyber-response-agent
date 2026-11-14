"""`python -m defender.api_server`: the platform API on PostgreSQL and Keycloak, settings from the environment."""

from __future__ import annotations

import os

import httpx

from . import run

if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    raise SystemExit(run(os.environ, transport=httpx.AsyncHTTPTransport()))
