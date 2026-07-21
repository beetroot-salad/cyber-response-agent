
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
from defender.scripts.adapters import faults

SYSTEM = "example"


def _config(ctx: VerbContext) -> dict[str, str]:
    path = ctx.defender_dir / "knowledge" / "environment" / "systems" / SYSTEM / "config.env"
    config: dict[str, str] = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"').strip("'")
    return config


def _request(ctx: VerbContext, path: str, params: dict[str, str] | None = None) -> Any:
    config = _config(ctx)
    base = config.get("URL_BASE")
    if not base:
        raise faults.ConfigFault(f"{SYSTEM}: URL_BASE is not set in config.env.")
    timeout = float(config.get("TIMEOUT_SEC", "10"))
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
                f"{SYSTEM}: authentication failed (HTTP {exc.code}). Check "
                f"AUTH_TYPE and the secret env var it names."
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
