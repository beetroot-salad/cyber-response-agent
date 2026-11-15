"""#1161 B3: the API's one mount prefix. Tests address the API as `API + path`, never a root path."""
from __future__ import annotations

from typing import Any

API = "/api"


def route_paths(routes: Any) -> list[str]:
    """The path of every route as served (FastAPI includes routers lazily, so walk their effective routes)."""
    found: list[str] = []
    for route in routes:
        if hasattr(route, "effective_candidates"):
            found.extend(route_paths(route.effective_candidates()))
        elif hasattr(route, "path"):
            found.append(route.path)
    return found
