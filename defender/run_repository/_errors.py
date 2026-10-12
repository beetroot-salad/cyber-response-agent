"""The runs repository's error types. How its refusals show a name is `defender._shown`'s
rule, shared with the tenant owner.

`RunRefused` is every refusal the repository makes that is not the tenant's (#1105 OP-5):
`RunId`'s, the lookups' and the episode record's. A fault of the tenant's runs folder or its
`_tenant.json` is `_tenant.TenantRefused` instead (P2) — except where a run is opened, which
answers one family: `RunAbsent` (the run is gone: nothing at its name, or no container at all)
and `RunUnreachable` (the container that holds it cannot be trusted or read right now), each a
`RunRefused`, the second raised `from` the container's `TenantRefused` (#1105 PR 2 review). It
is a plain `Exception`, not a `ValueError`, so neither error's handler ever catches the other.

Pydantic-free: `RunId` imports it, and in-box code may import `RunId` (NM-05).
"""
from __future__ import annotations

from defender._shown import escaped


class RunRefused(Exception):  # noqa: N818 — the design's name (#1105 OP-5), as `TenantRefused`
    """The repository refused: a bad run id, an unexpected entry in a runs folder, a corrupt
    episode record, or a write it will not make. The message names the path and the fault.

    The message is `escaped` when the refusal is built, so no path or name spliced into it —
    the runs folder's own path included — can break its one line, whichever site raised it
    (an escaped message escapes to itself, so a re-built or unpickled refusal is unchanged)."""

    def __init__(self, message: object = "") -> None:
        super().__init__(escaped(message))


class RunAbsent(RunRefused):
    """The repository refused because the run is gone: nothing at its name, or no container
    where it would live — told apart from an entry that is there but is not a run (a file, a
    link), which stays a plain `RunRefused` (#1105 rev 5.1 S4). A subclass, so every existing
    `except RunRefused` handler still catches it; a caller that must tell absent from refused
    catches this first."""


class RunUnreachable(RunRefused):
    """The repository refused to open a run because the container that holds it cannot be
    trusted or read right now: a link or a non-directory where it stands, or a `_tenant.json`
    missing, corrupt or naming another tenant. Raised `from` the container's `TenantRefused`
    (#1105 PR 2 review), so an open answers one refusal family; the run may well be there."""
