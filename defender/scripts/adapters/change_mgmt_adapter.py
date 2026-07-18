"""Change-mgmt stub adapter — the `change-mgmt` VERBS registry.

Wraps the v2 playground change-management stub. Read-only verbs only —
the `POST /changes` and transition surfaces are chaos-mode controls,
not investigation reads.

Verbs (`VERBS` is the whole model-facing surface — there is no CLI):
    health-check
    active-changes  host, at
    get-change      cr_id
    list-changes    [status] [host] [active_at]

Faults (`faults.py`): ConfigFault/TransportFault = infra (2), UpstreamFault = query
error (1) — including a non-UTC `at`, which is the agent's mistake to fix.
"""

from __future__ import annotations

import re

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (see cmdb_adapter.py).
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
# UTC ISO 8601 — Z suffix or explicit offset. Loose: caller-side discipline
# is more useful than a strict parser, but reject obvious "2026-04-24" / local
# time forms so missing-Z bugs don't reach the upstream silently.
ISO_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)




def _require_utc(value: str) -> str:
    """A non-UTC timestamp is an `UpstreamFault` (a query error, exit 1) even though we
    catch it locally: it is the AGENT's mistake, and the digest names the concrete fix —
    which is exactly what the pitfalls curator reads."""
    if not ISO_UTC_RE.match(value):
        raise UpstreamFault(
            f"`at` must be UTC ISO 8601 (e.g. 2026-04-24T12:00:00Z), got: {value!r} — "
            f"change-mgmt active-window queries are timezone-sensitive; pass an explicit "
            f"Z or +00:00 suffix."
        )
    return value


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, transport.load_config(ctx, SYSTEM, PREFIX), SYSTEM)


def active_changes(ctx: VerbContext, *, host: str, at: str) -> dict | list:
    params = {"host": host, "at": _require_utc(at)}
    return transport.http_get(ctx, transport.load_config(ctx, SYSTEM, PREFIX), "/changes/active", params=params)


def get_change(ctx: VerbContext, *, cr_id: str) -> dict:
    return transport.http_get_obj(ctx, transport.load_config(ctx, SYSTEM, PREFIX), f"/changes/{cr_id}")


def list_changes(
    ctx: VerbContext,
    *,
    status: str | None = None,
    host: str | None = None,
    active_at: str | None = None,
) -> dict | list:
    params: dict[str, str] = {}
    if status:
        # The CLI enforced this with argparse `choices`; a verb has no argparse, so the
        # closed enum is checked here — and a bad value is the agent's to fix (exit 1).
        if status not in STATUSES:
            raise UpstreamFault(
                f"unknown status {status!r} — change-mgmt statuses are {list(STATUSES)}."
            )
        params["status"] = status
    if host:
        params["host"] = host
    if active_at:
        params["active_at"] = _require_utc(active_at)
    return transport.http_get(ctx, transport.load_config(ctx, SYSTEM, PREFIX), "/changes", params=params or None)


VERBS = {
    "health-check": health_check,
    "active-changes": active_changes,
    "get-change": get_change,
    "list-changes": list_changes,
}
