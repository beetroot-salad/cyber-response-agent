
from __future__ import annotations

import re

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import UpstreamFault

SYSTEM = "change-mgmt"
PREFIX = "CHANGE_MGMT"
STATUSES = ("planned", "approved", "in_progress", "implemented", "cancelled")
ISO_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX)


def _require_utc(value: str) -> str:
    if not ISO_UTC_RE.match(value):
        raise UpstreamFault(
            f"`at` must be UTC ISO 8601 (e.g. 2026-04-24T12:00:00Z), got: {value!r} — "
            f"change-mgmt active-window queries are timezone-sensitive; pass an explicit "
            f"Z or +00:00 suffix."
        )
    return value


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def active_changes(ctx: VerbContext, *, host: str, at: str) -> dict | list:
    params = {"host": host, "at": _require_utc(at)}
    return transport.http_get(ctx, _config(ctx), "/changes/active", params=params)


def get_change(ctx: VerbContext, *, cr_id: str) -> dict:
    return transport.http_get_obj(ctx, _config(ctx), f"/changes/{cr_id}")


def list_changes(
    ctx: VerbContext,
    *,
    status: str | None = None,
    host: str | None = None,
    active_at: str | None = None,
) -> dict | list:
    params: dict[str, str] = {}
    if status:
        if status not in STATUSES:
            raise UpstreamFault(
                f"unknown status {status!r} — change-mgmt statuses are {list(STATUSES)}."
            )
        params["status"] = status
    if host:
        params["host"] = host
    if active_at:
        params["active_at"] = _require_utc(active_at)
    return transport.http_get(ctx, _config(ctx), "/changes", params=params or None)


VERBS = {
    "health-check": health_check,
    "active-changes": active_changes,
    "get-change": get_change,
    "list-changes": list_changes,
}
