
from __future__ import annotations

from typing import TYPE_CHECKING

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import VerbContext
from defender.kit import transport
from defender.kit.faults import UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "threat-intel"
PREFIX = "THREAT_INTEL"
VERDICTS = ("benign", "suspicious", "malicious", "unknown")


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX)


def _timeout(ctx: VerbContext) -> int:  # lint-dup: ok — per-module alias over the shared transport.timeout_of
    return transport.timeout_of(_config(ctx))


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` a verb here can raise —
    `_config`'s keys and the access declaration — raised over the run's record, or None when
    the system is usable."""
    transport.check_settings_of(tenant, SYSTEM, PREFIX)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, SYSTEM, timeout_sec=_timeout(ctx))


def lookup(ctx: VerbContext, *, value: str) -> dict:
    return transport.request(ctx, SYSTEM, "GET", "/lookup/{value}", {"value": value},
                             timeout_sec=_timeout(ctx))


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
    return transport.request(ctx, SYSTEM, "GET", "/indicators", query=params or None,
                             timeout_sec=_timeout(ctx), answer="any")


VERBS = {
    "health-check": health_check,
    "lookup": lookup,
    "list-indicators": list_indicators,
}
