
from __future__ import annotations

import contextlib
import errno
import json
import os
import sys
from pathlib import Path

from defender._io import guarded_mkdir
from defender._run_paths import LEAD_ID_RE, RunPaths  # noqa: F401 — re-export: this module is the claim gate's import surface

#: `claim_lead`'s three answers. Three, because a caller has to tell "the row is on disk and
#: this dispatch owns the id" from "nothing was written". If success and every silent skip
#: shared one code, a `goal=""` (the tool schema admits a bare `str`) would dispatch gather
#: under an id with NO leads row — and nothing then bounds how many sessions run under that id,
#: since the reuse gate IS the sidecar's `O_EXCL` create, so each would overwrite the last one's
#: `gather_summaries/{id}.md`.
CLAIMED = 1
NOT_CLAIMED = 0
ALREADY_CLAIMED = 2


def claim_lead(dispatch: dict) -> int:
    """Write this lead's leads-table row and claim its id, atomically. Returns `CLAIMED` only
    when the sidecar was created BY THIS CALL; `ALREADY_CLAIMED` when the id was already taken
    (the `O_EXCL` reuse gate); `NOT_CLAIMED` for every other outcome — a dispatch the shape
    checks refuse, and any filesystem fault. Never raises: the contract is a code."""
    run_dir = dispatch.get("run_dir")
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []

    # `.strip()` as well as truthiness: the body below records the STRIPPED goal, so a
    # whitespace-only goal would claim the id and write a leads row whose goal is `""` — the
    # same empty row the falsy arm refuses.
    if not run_dir or not lead_id or not goal or not str(goal).strip():
        return NOT_CLAIMED
    if not isinstance(wtc, list):
        return NOT_CLAIMED
    if not LEAD_ID_RE.match(str(lead_id)):
        return NOT_CLAIMED

    sidecar_dir = RunPaths(Path(run_dir)).gather_raw
    try:
        guarded_mkdir(sidecar_dir, base=Path(run_dir))
    except (OSError, ValueError):
        # ValueError as well as OSError: `guarded_mkdir` raises it for a target outside the
        # tree the anchor names. This hook's whole contract is "return a code, never raise".
        return NOT_CLAIMED

    sidecar_path = sidecar_dir / f"{lead_id}.lead.json"
    body: dict = {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}
    provenance = dispatch.get("provenance")
    if provenance:
        # Written only when the caller names one (the harness's own reserved-id claims) — an
        # absent field reads as model-authored.
        body["provenance"] = str(provenance)
    payload = json.dumps(body, indent=2) + "\n"

    try:
        fd = os.open(sidecar_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as e:
        if e.errno == errno.EEXIST:
            print(
                f"lead_id {lead_id!r} already dispatched; append a new :L "
                f"findings row and echo its id (a retry is a new lead, never "
                f"a reused id).",
                file=sys.stderr,
            )
            return ALREADY_CLAIMED
        return NOT_CLAIMED
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except OSError:
        # THE ONLY branch where this hook still owns `fd`: `fdopen` takes ownership when it
        # succeeds. Close to unreachable (`fd` is a freshly created regular file), but kept so
        # the never-took-ownership path stays covered.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return NOT_CLAIMED
    try:
        with fh:
            fh.write(payload)
    except OSError:
        # No `os.close(fd)`. The `with` closes the fd on the way out INCLUDING when the failure
        # is the implicit flush inside `close()` — the ENOSPC/EDQUOT/EIO case this arm exists
        # for — so a second `os.close(fd)` would hit EBADF or, worse, whatever unrelated
        # descriptor the OS had since handed that same number, silently. The race is real:
        # `claim_lead` runs on the event-loop thread while lead-0's fire-and-forget correlation
        # task issues adapter calls through `asyncio.to_thread` into `subprocess.run`, which
        # opens pipes.
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return NOT_CLAIMED
    return CLAIMED
