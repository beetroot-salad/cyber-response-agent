
from __future__ import annotations

import contextlib
import errno
import json
import os
import sys
from pathlib import Path

from defender._io import guarded_mkdir
from defender._run_paths import LEAD_ID_RE, RunPaths  # noqa: F401 — re-export: this module is the claim gate's import surface

#: `claim_lead`'s answers. Success must be distinguishable from "nothing was written": the
#: sidecar's `O_EXCL` create is the only id-reuse gate, so dispatching without a row would let
#: unbounded sessions share an id and overwrite each other's `gather_summaries/{id}.md`.
CLAIMED = 1
NOT_CLAIMED = 0
ALREADY_CLAIMED = 2


def _say_already_dispatched(lead_id: object) -> None:
    """The model's remedy for a taken id, on stderr — the same for both `ALREADY_CLAIMED`
    arms, since to the model they are indistinguishable."""
    print(
        f"lead_id {lead_id!r} already dispatched; append a new :L "
        f"findings row and echo its id (a retry is a new lead, never "
        f"a reused id).",
        file=sys.stderr,
    )


def _claim_path(run_dir: Path, lead_id: str) -> Path | int:
    """The claim sidecar's path under a `gather_raw/` this call could create — or the code the
    hook answers with when it could not."""
    paths = RunPaths(run_dir)
    try:
        guarded_mkdir(paths.gather_raw, base=run_dir)
    except (OSError, ValueError):
        # `guarded_mkdir` raises ValueError for a target outside the anchor; never raise here.
        return NOT_CLAIMED
    try:
        return paths.lead_claim(lead_id)
    except ValueError:
        # Not a plain single segment: nobody holds the name, so not the taken-id answer.
        return NOT_CLAIMED
    except OSError:
        # An entry planted at the claim's name resolves outside the run dir. Something holds
        # the name, as EEXIST would say, so answer the same way (alias refusals are exempt from
        # failure circuits).
        _say_already_dispatched(lead_id)
        return ALREADY_CLAIMED


def claim_lead(dispatch: dict) -> int:
    """Write this lead's leads-table row and claim its id, atomically. `CLAIMED` only when this
    call created the sidecar; `ALREADY_CLAIMED` when the id was taken; `NOT_CLAIMED` for a
    refused dispatch or any filesystem fault. Never raises."""
    run_dir = dispatch.get("run_dir")
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []

    # The stripped goal is recorded, so a whitespace-only goal is as empty as a missing one.
    if not run_dir or not lead_id or not goal or not str(goal).strip():
        return NOT_CLAIMED
    if not isinstance(wtc, list):
        return NOT_CLAIMED
    if not LEAD_ID_RE.match(str(lead_id)):
        return NOT_CLAIMED

    sidecar_path = _claim_path(Path(run_dir), lead_id)
    if isinstance(sidecar_path, int):
        return sidecar_path
    body: dict = {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}
    provenance = dispatch.get("provenance")
    if provenance:
        # Absent means model-authored; the harness names one for its reserved-id claims.
        body["provenance"] = str(provenance)
    payload = json.dumps(body, indent=2) + "\n"

    try:
        fd = os.open(sidecar_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as e:
        if e.errno == errno.EEXIST:
            _say_already_dispatched(lead_id)
            return ALREADY_CLAIMED
        return NOT_CLAIMED
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except OSError:
        # The only branch where this hook still owns `fd`; `fdopen` takes it on success.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return NOT_CLAIMED
    try:
        with fh:
            fh.write(payload)
    except OSError:
        # No `os.close(fd)`: the `with` already closed it, even when the failure is the flush
        # in `close()` (ENOSPC/EDQUOT/EIO). A second close could hit a descriptor another
        # thread has since been handed the same number for (adapter subprocess pipes).
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return NOT_CLAIMED
    return CLAIMED
