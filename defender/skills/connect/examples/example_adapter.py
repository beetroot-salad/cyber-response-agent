
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[4])) not in _sys.path:
    _sys.path.insert(0, _root)

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import _stub_transport, faults

SYSTEM = "example"
#: The prefix this system's `config.env` keys carry: the folder name, upper-cased
#: (`systems/example/config.env` holds `EXAMPLE_URL_BASE=...`).
PREFIX = "EXAMPLE"


def _config(ctx: VerbContext) -> dict[str, str]:
    """This system's settings, from the run's record (`ctx.tenant.systems`) — resolved once when
    the run began. Never the settings folder as it is now and never the process environment: an
    adapter reads its configuration from the record, so an exported variable changes nothing a
    run addresses. (A credentialed system has no secret delivery yet: #1163.)
    `load_config` strips the prefix and raises `ConfigFault` (infra, exit 2) for a system with no
    config, or a missing or blank required key. This adapter calls its system directly, so its
    config.env declares no docker access method (`EXAMPLE_TRANSPORT` / `EXAMPLE_DOCKER_CONTEXT`)."""
    return _stub_transport.load_config(ctx, SYSTEM, PREFIX, ("URL_BASE", "TIMEOUT_SEC"))


def _request(ctx: VerbContext, path: str, params: dict[str, str] | None = None) -> Any:
    config = _config(ctx)
    base = config["URL_BASE"]
    timeout = float(config["TIMEOUT_SEC"])
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code in (401, 403):
            raise faults.TransportFault(
                f"{SYSTEM}: authentication failed (HTTP {exc.code}). This system needs a "
                f"credential, and credential delivery is not supported yet (#1163)."
            ) from exc
        raise faults.UpstreamFault(body or f"{SYSTEM}: query rejected (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise faults.TransportFault(f"{SYSTEM}: cannot reach {base} ({exc}).") from exc


def health_check(ctx: VerbContext) -> dict:
    _request(ctx, "/health")
    return {"system": SYSTEM, "status": "connected"}


@verb(engine="lucene", body_param="native_query")
def query(ctx: VerbContext, *, native_query: str, limit: int = 100) -> dict | list:
    return _request(ctx, "/events", {"q": native_query, "limit": str(limit)})


def get_record(ctx: VerbContext, *, id: str) -> dict:
    return _request(ctx, f"/records/{id}")


VERBS = {
    "health-check": health_check,
    "query": query,
    "get-record": get_record,
}
