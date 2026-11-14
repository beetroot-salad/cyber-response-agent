"""The platform API as a program on PostgreSQL and Keycloak (#1083): `python -m defender.api_server`.

The program owns every start and stop step (settings, version check, Keycloak probes, bind, bootstrap, serve,
close); uvicorn only serves the socket it is handed. Piece 2 and the demo server (`defender.api.serve`) are separate."""

from __future__ import annotations

from ._program import Running, run, serving
from ._settings import Settings, StartRefused

__all__ = ["Running", "Settings", "StartRefused", "run", "serving"]
