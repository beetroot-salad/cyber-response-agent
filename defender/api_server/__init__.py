"""The platform API as a program on PostgreSQL, the sign-in server and the secret store (#1083): `python -m defender.api_server`.

The program owns every start and stop step (settings, version check, the secret store's seal status and login, sign-in
server probes, the adapter catalog, bind, bootstrap, serve, close); uvicorn only serves the socket it is handed."""

from __future__ import annotations

from ._program import Running, api_deps, run, serving
from ._settings import Settings, StartRefused

__all__ = ["Running", "Settings", "StartRefused", "api_deps", "run", "serving"]
