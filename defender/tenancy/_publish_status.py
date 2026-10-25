"""The tenant's last publish outcome (#1108 P4 O-SEE): `<T>/publish-status.json`.

Every publish trigger records its outcome here — the refusal with its kind (`transient`, an
outage that may pass by itself, or `operator`, one that needs a human), or the commit it
published (which clears the refusal) — so `tenant.py check` can say why `current` trails
`origin/main` instead of staying silent. Plain file writes: the run launcher records the
outcomes only it sees (a publish child that crashed or was stopped) without importing tenant
delivery (P-3), through the same `record_report` the child records its own report with.
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime

from defender import _io
from defender._text import one_line
from defender.tenancy._tenant import Tenant

TRANSIENT = "transient"
OPERATOR = "operator"
#: The launch-time publish's report vocabulary (OD2): each line's first word. Defined once here,
#: below both the child that writes a line and run start that reads it.
FRESH = "fresh"
STALE_PREFIX = "stale:"
STALE_TRANSIENT = f"{STALE_PREFIX}{TRANSIENT}"
STALE_OPERATOR = f"{STALE_PREFIX}{OPERATOR}"
MISCONFIGURED = "misconfigured"


def _recorded_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write(tenant: Tenant, record: dict) -> None:
    """Best effort: a status that cannot be written never hides the outcome it records."""
    with contextlib.suppress(OSError):
        _io.write_guarded(tenant.publish_status, json.dumps(record, sort_keys=True) + "\n")


def record_published(tenant: Tenant, commit: str, *, by: str) -> None:
    """A publish by `by` (the trigger) succeeded at `commit`: any earlier refusal is over."""
    _write(tenant, {"at": _recorded_at(), "by": by, "published": commit})


def record_refusal(tenant: Tenant, *, kind: str, reason: str, by: str) -> None:
    """A publish by `by` was refused: `kind` (`TRANSIENT` or `OPERATOR`) and why."""
    if kind not in (TRANSIENT, OPERATOR):
        raise ValueError(f"{kind!r} is not a publish refusal kind")
    _write(tenant, {"at": _recorded_at(), "by": by, "refused": one_line(reason), "kind": kind})


def record_report(tenant: Tenant, line: str, *, by: str) -> None:
    """The outcome a launch-time publish report `line` states, recorded as `by`'s: `fresh`
    publishes its commit; `stale:transient` is a transient refusal; `stale:operator` and
    `misconfigured` need a human. The one recorder for the child and the launcher alike, so the
    recorded outcome is always the reported one."""
    head, _sep, rest = line.strip().partition(" ")
    if head == FRESH:
        record_published(tenant, rest, by=by)
        return
    kind = TRANSIENT if head == STALE_TRANSIENT else OPERATOR
    record_refusal(tenant, kind=kind, reason=rest, by=by)


def read_status(tenant: Tenant) -> dict | None:
    """The last publish outcome recorded, or `None` when none is (or it cannot be read)."""
    try:
        text = _io.read_text_utf8(tenant.publish_status)
    except OSError:
        return None
    obj, bad = _io.load_json_artifact(text)
    return obj if bad is None and isinstance(obj, dict) else None
