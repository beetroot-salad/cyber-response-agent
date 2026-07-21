
from __future__ import annotations

import urllib.parse

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import UpstreamFault

SYSTEM = "threat-intel"
PREFIX = "THREAT_INTEL"
VERDICTS = ("benign", "suspicious", "malicious", "unknown")


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def lookup(ctx: VerbContext, *, value: str) -> dict:
    quoted = urllib.parse.quote(value, safe="")
    return transport.http_get_obj(ctx, _config(ctx), f"/lookup/{quoted}")


def list_indicators(
    ctx: VerbContext,
    *,
    verdict: str | None = None,
    type: str | None = None,  # noqa: A002 — the stub's own query param name; `${type}` in the templates
    tag: str | None = None,
) -> dict | list:
    params: dict[str, str] = {}
    if verdict:
        if verdict not in VERDICTS:
            raise UpstreamFault(
                f"unknown verdict {verdict!r} — threat-intel verdicts are {list(VERDICTS)}."
            )
        params["verdict"] = verdict
    if type:
        params["type"] = type
    if tag:
        params["tag"] = tag
    return transport.http_get(ctx, _config(ctx), "/indicators", params=params or None)


VERBS = {
    "health-check": health_check,
    "lookup": lookup,
    "list-indicators": list_indicators,
}
