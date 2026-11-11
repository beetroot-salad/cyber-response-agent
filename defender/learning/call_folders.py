"""The learning curators' call folders (#1278 A1, P7): one private, host-made folder per curator call.

A curator stage runs a model with no run of its own; the agent binding needs a run folder, so each call is
handed a folder of its own under the tenant's scratch location (`Tenant.scratch`, A2 D10): neither the
learning state, nor under a batch draft, nor in any box mount. It holds only that call's trace
(`wire_logs/`, written by the stage harness, format unchanged until #1082 takes it over). Nothing here
deletes a folder (O9).

A call is named by its drain batch id, its stage (`lessons`, `questioner`, `pitfalls`, `feedback`) and its ordinal within
that stage of the batch, counted from 1 (G-A1).
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from defender import _io
from defender.records.formats import unwrap_scratch_root

if TYPE_CHECKING:
    from defender.tenancy import Tenant

#: The curator stages a call folder is made for, in the order the drains run them.
STAGES = ("lessons", "questioner", "pitfalls", "feedback")


def call_folder(tenant: Tenant, batch_id: str, stage: str, ordinal: int, *, make: bool = False) -> Path:
    """The folder of the `ordinal`-th `stage` call of drain batch `batch_id`, below `tenant`'s scratch
    location: `<scratch>/<batch_id>-<stage>-<ordinal>`. With `make`, the folder is made (the scratch
    location too, if missing), judged no-follow: a link, file or anything but a folder already at its
    name refuses the call (`OSError`) and nothing is created through it (G-A2). A folder already there
    is adopted. `ValueError` for a key that cannot name one folder."""
    if stage not in STAGES:
        raise ValueError(f"{stage!r} is not a curator stage ({', '.join(STAGES)})")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
        raise ValueError(f"{ordinal!r} is not a call ordinal (an integer from 1)")
    if not isinstance(batch_id, str) or not batch_id or "/" in batch_id or "\0" in batch_id or batch_id.startswith("."):
        raise ValueError(f"{batch_id!r} does not name a drain batch (one path segment)")
    scratch = unwrap_scratch_root(tenant.scratch)
    name = f"{batch_id}-{stage}-{ordinal}"
    if make:
        with _io.hold_new(scratch.parent, scratch.name) as held, _io.hold_under(held, name, create=True):
            pass
    return scratch / name
