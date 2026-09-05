"""The clerk's shared contract — the handful of facts BOTH halves of the port need.

`runtime/clerk.py` owns the caller and `runtime/tools/_clerk.py` owns the `record` verb, and
the two import each other's world: the verb needs the round budget, the pending cap, the
malformed-reply class and the trace file's location; the caller needs `AgentDeps`, which lives
under `runtime.tools`. Spelled in either of those modules, that is an import CYCLE —
`import defender.runtime.clerk` first raises `ImportError`, and it only ever worked because
every entry point in the tree happens to reach `runtime.tools` first. A script whose first
defender import is the clerk (the #986 dry-run script is one) breaks on import order alone.

So the shared facts live HERE, in a leaf that imports nothing from `runtime`, for the same
reason `_wire.py` exists: two hand-identical spellings in modules that do not import each
other drift silently. `runtime/clerk.py` re-exports every name below under its own `__all__`,
which is where a reader already imports them from.
"""

from __future__ import annotations

from pathlib import Path

#: D2/D7's shared budget: repair rounds and round-loop rounds draw from ONE pool of six clerk
#: invocations per `record` call — never two independent pools of six. HD-4 also fixes
#: `pending`'s own cap at this same number.
CLERK_ROUND_BUDGET = 6

#: HD-4: `pending` holds at most six entries; the oldest is dropped on overflow, with a
#: receipt line naming what was lost.
PENDING_CAP = 6

#: `(prose, held_block, owed)` — a provider fault pushes `(prose, None, [])`; a D7 judgment
#: stop or an S6 conclude-drop pushes `(prose, block, owed)`.
PendingCompile = tuple[str, "str | None", tuple[str, ...]]


class ClerkMalformedReply(Exception):
    """The clerk answered with text the round loop cannot split into fences OR a `GAPS:`
    section at all — what a model that lost the format and answered in prose produces.
    Treated identically to a transport fault: pend the prose, write the trace, return."""


def clerk_trace_path(run_dir: Path) -> Path:
    """`<run_dir>/wire_logs/clerk_trace.jsonl`, for the WRITER (`tools/_clerk._append_trace`)
    and the RESUME READER (`clerk._highest_clerk_trace_n`) alike.

    ONE spelling, the way `challenge_gate.review_trace_path` owns its own filename: the reader
    seeds `record_n` so a resumed process cannot re-issue a trace identity a prior pass already
    used (HD-2's one excepted piece of state), and a reader spelling this path independently of
    the writer finds no file the day the wire-log component moves — seeding zero, silently, on
    exactly the resume the seeding exists for.

    PURE: it joins and returns. The mkdir belongs to the one writer, so a reader asking where
    the file is never leaves an empty `wire_logs/` behind."""
    from defender._run_paths import WIRE_LOG_DIR

    return Path(run_dir) / WIRE_LOG_DIR / "clerk_trace.jsonl"


__all__ = [
    "CLERK_ROUND_BUDGET",
    "PENDING_CAP",
    "ClerkMalformedReply",
    "PendingCompile",
    "clerk_trace_path",
]
