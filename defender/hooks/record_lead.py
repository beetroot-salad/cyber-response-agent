"""Leads-table write + lead_id claim — a LIBRARY, not a hook.

Writes the leads-table row `{run_dir}/gather_raw/{lead_id}.lead.json` =
`{goal, what_to_summarize}`.

`lead_id` is the `:L` invlang row id the defender echoes from the
already-authored `:L findings` row (e.g. `l-001`) — not a new id minted
here. It is the FK the queries table (`record_query.py`) and the read
surface (`learning/lead_repository.py`) join on.

The write is an atomic exclusive create (`O_CREAT|O_EXCL`): one syscall
that both persists the row and detects a reused id. Parallel leads dispatch
concurrently — distinct ids claim distinct paths and all succeed; a genuine
reuse (same id twice in a batch, or across turns) fails the exclusive create
and `claim_lead` returns **2**. The sole consumer, `runtime/tools_gather.py`'s
`_run_gather`, turns that into a `ModelRetry` before gather is spawned, so no
orphan query row is written and the defender bounces back to PLAN. The
remediation fed back to the agent is to append a fresh `:L` findings row and
echo its id (a retry is a new lead, never a reused id — append-only invlang).

`claim_lead` returns 0 on a benign skip (missing fields / malformed lead_id /
plumbing error) — never block a dispatch over an extraction issue; only a real
reuse collision returns 2.

This module used to double as a `claude -p` PreToolUse hook script that read the
dispatch off a Task tool call's prompt (stdin JSON in, exit code out). That
runtime and its `run-settings.json` wiring were retired, so the entrypoint went
with them — and with it the lenient prompt-YAML parser (`extract_dispatch` /
`_parse_block`) that existed only to recover these fields from prompt text. The
caller passes the typed dispatch fields directly now.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import sys
from pathlib import Path

from defender._run_paths import RunPaths

# A lead_id is the `:L` row id: `l-` + alphanumerics. Grammar mirrors the
# invlang parser's lead-id grammar and scripts/gather_tools/record_query.py's --lead
# guard — keep in sync. Used verbatim as a path segment and FK.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")


def claim_lead(dispatch: dict) -> int:
    """Write the leads-table row exclusively, claiming the lead_id.

    Returns 0 on a claim or a benign skip (missing fields / malformed
    lead_id / plumbing error — never block a dispatch over these), and 2
    on a reuse collision (the id's sidecar already exists).
    """
    run_dir = dispatch.get("run_dir")
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []

    if not run_dir or not lead_id or not goal:
        return 0
    if not isinstance(wtc, list):
        return 0
    if not LEAD_ID_RE.match(str(lead_id)):
        return 0

    sidecar_dir = RunPaths(Path(run_dir)).gather_raw
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0

    sidecar_path = sidecar_dir / f"{lead_id}.lead.json"
    payload = json.dumps(
        {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}, indent=2
    ) + "\n"

    # Atomic exclusive create: one syscall persists the row AND detects a
    # reused id. Only EEXIST is a hard error (exit 2); any other OSError
    # fails open (exit 0) — losing the sidecar is acceptable, blocking a
    # dispatch over plumbing is not.
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
            return 2
        return 0
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
    except OSError:
        # Don't leave a 0-byte sidecar: load_leads would skip it (degrading the
        # lead to an orphan) AND it would become a false reuse token that
        # rejects a legitimate same-id retry with EEXIST. Best-effort: close a
        # leaked fd (if fdopen never took ownership) and remove the empty file.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return 0
    return 0
