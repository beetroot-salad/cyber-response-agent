"""Resume a finished investigation from one of its own messages, in a sibling world.

The turn-N branch (`docs/learning-architecture-redesign.md` §The turn-N branch) forks a real
run at the moment its evidence is in hand and continues it under a world that differs from the
one it actually ran in. This module owns the two things that makes possible: WHICH message may
be branched from, and WHERE the forked session lives.

`session_store.fork()` is not touched. It is correct — it seeds the child's `last_render_len`
to the SEND-role length of the inherited prefix, and `test_session_head_fork_754.py` pins that.
What was missing is the CALLER contract: a fresh `agent.iter` starts the framework's message
list empty, so the prefix has to be handed back as `message_history` or `selection.ingest`
underflows against a store that was already right. `driver.run_investigation` does that by
hydrating the fork it just opened; the symmetry is exact rather than approximate, because
`fork` and `hydrate(role="send")` truncate through the same `_complete_prefix_len`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths

from . import session_store


class BranchError(Exception):
    """A branch point that cannot carry a sibling world."""


@dataclass(frozen=True)
class BranchSpec:
    """One resume: which run, which message, and what to say on arrival.

    `continuation_prompt` is a PARAMETER rather than something this module composes, and that
    is deliberate — the 2026-08-16 experiment's own caveat was that its continuation wording
    ("close it when the evidence supports a disposition") biased the run toward closing over
    gathering. The prompt is part of the measured instrument, so it belongs to whoever is
    running the measurement, not to the seam.
    """

    source_run_dir: Path
    branch_message_id: int
    continuation_prompt: str


def open_source_store(run_dir: Path) -> Any:
    """The finished run's OWN store, opened for writing.

    A sibling gets a fresh run dir for its own artifacts but forks INTO the source database:
    the prefix rows live there, and `fork` walks parents inside one transaction, so a child in
    any other file would inherit nothing. The case pointer is what makes the source store
    findable from a run dir alone.

    `runs_base` is derived the way the WRITER derived it — `run_dir.parent`, exactly as
    `driver._default_store_factory` did when this store was created — and then CHECKED against
    the path the writer recorded. The check is not defensive noise: `store_path_for` resolves
    to `runs_base.parent / "sessions"`, so a `runs_base` off by one directory level still names
    a well-formed path, and `open_store` creates-if-missing. A wrong derivation therefore
    returns a live handle over an EMPTY database and the fault surfaces far away, as
    `main_session_id` finding no root session in a store that was never the right one.
    """
    run_dir = Path(run_dir)
    recorded = Path(session_store.resolve_store_path(run_dir))
    pointer = json.loads(
        (run_dir / session_store.POINTER_FILENAME).read_text(encoding="utf-8"))
    case_id = pointer["case_id"]
    derived = session_store.store_path_for(case_id, runs_base=run_dir.parent)
    if derived != recorded:
        raise BranchError(
            f"{run_dir} records its store at {recorded}, but its case {case_id!r} under "
            f"runs_base {run_dir.parent} resolves to {derived} — opening the derived path "
            "would create an empty database and lose the branch point")
    return session_store.open_store(case_id=case_id, runs_base=run_dir.parent)


def store_factory_for(spec: BranchSpec):
    """A `driver.StoreFactory` that hands back the source run's store.

    Signature is the factory's, `(case_id, run_dir)`, and BOTH arguments are ignored: a resumed
    run does not mint a case, it joins one. Taking them anyway is what lets the resume ride the
    seam `run_investigation` already has instead of growing a second one.
    """
    def factory(case_id: str, run_dir: Path) -> Any:  # noqa: ARG001 — the factory's shape
        return open_source_store(spec.source_run_dir)

    return factory


def fence_count_at(store: Any, session_id: str, branch_message_id: int) -> int:
    """How many invlang fences had landed by `branch_message_id`.

    `frontier_at` counts FENCES, not messages, and says so in its own docstring — "a caller
    holding a message index maps it to a fence itself, because only the run's trace can do
    that." This is that caller, and it reads the STORE rather than `tool_trace.jsonl`: the
    trace's rows are `{message, timestamp, type}`, carrying neither a tool name nor a message
    id, so the mapping cannot be recovered from it. The store's message rows carry both, and
    the `actor` read role publishes `tool_name` per path row in path order.

    COARSE, like the thing it feeds. A fence lands per `append_block`, so many message-level
    branch points share one frontier — `frontier_at` says the same of itself and reports
    `snapped` when a caller asks past the end.
    """
    ids = session_store.path_row_ids(store, session_id)
    rows = session_store.hydrate(store, session_id, role="actor")
    return sum(
        1 for row_id, row in zip(ids, rows, strict=True)
        if row_id <= branch_message_id and row.get("tool_name") == "append_block"
    )


def frontier_at_branch(store: Any, spec: BranchSpec):
    """The investigation's open state as it stood at the branch point."""
    from defender._io import read_text_soft
    from defender.skills.invlang.frontier import frontier_at

    session_id = session_store.main_session_id(store)
    text, _ = read_text_soft(RunPaths(Path(spec.source_run_dir)).investigation)
    return frontier_at(
        text or "", fence_count_at(store, session_id, spec.branch_message_id))


def validate(store: Any, spec: BranchSpec) -> None:
    """Refuse a branch point that cannot carry a sibling world.

    TWO preconditions, and both are about the same thing — a world is only meaningfully
    "consistent with the evidence" when there IS evidence and there IS something unresolved.

    **A non-empty capture.** At message 0 the adapters have returned nothing, so every proposed
    world is trivially consistent with the prefix and the captured base guards nothing. That is
    the generated-world design the redesign rejected, reached by branching too early rather
    than by choosing it.

    **A non-empty frontier.** `frontier_at` answers the empty frontier for a fence-less
    document, and an empty frontier is nothing open to discriminate — the pair would have no
    question to divide.
    """
    run_dir = Path(spec.source_run_dir)
    if spec.branch_message_id <= 0:
        raise BranchError(
            f"branch_message_id must be a real message, got {spec.branch_message_id} — "
            "message 0 precedes every payload, so no world can contradict the prefix")

    rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    if not rows:
        raise BranchError(
            f"{run_dir} captured no queries — a sibling world would be consistent with an "
            "empty prefix by construction, which is the generated-world design, not a branch")

    frontier = frontier_at_branch(store, spec)
    if frontier.frontier.is_empty():
        raise BranchError(
            f"the frontier at message {spec.branch_message_id} is empty "
            f"(fence {frontier.n} of {frontier.total}) — nothing is open there for a pair of "
            "worlds to divide")


def framework_view(prefix: list) -> list:
    """The prefix as the FRAMEWORK will hold it, which is not always as the store holds it.

    `pydantic_ai` normalises a handed-in `message_history` before the first request, and part
    of that is MERGING ADJACENT `ModelRequest`s. The store deliberately produces exactly that
    shape: #808's correlation lead is a synthesized `ModelRequest` written straight into MAIN's
    session, landing next to the tool-return `ModelRequest` before it. Measured: a four-message
    prefix of that shape comes back as three.

    Both `fork` and `hydrate` count STORE ROWS, and the framework does not — so the fork↔hydrate
    symmetry is exact and still insufficient. One merge and `len(live)` equals `last_render_len`
    at the first ingest, the tail slice is empty, the opening prompt is never stored, and the
    render hands back a list ending on a `ModelResponse` that the framework then refuses. Two
    merges and it underflows instead.

    So the count and the thing counted come from the SAME call. The framework's own function is
    used rather than a local "merge adjacent requests" of our own: the rule is theirs, and a
    reimplementation is a second spelling that drifts the day they normalise anything else.
    """
    from pydantic_ai._agent_graph import _clean_message_history

    return _clean_message_history(list(prefix))


def open_main_session(store: Any, spec: BranchSpec | None) -> tuple[str, list | None]:
    """MAIN's session for this run, and the history it starts from.

    THE one place the fresh/resumed choice is made, so the driver's composition root stays a
    straight line and the two cases cannot drift apart. A fresh run gets a new session and
    `None` — `agent.iter`'s own empty list is exactly right when nothing is inherited.

    A resume forks and hands back the prefix through `hydrate(role="send")`, because that is
    the SAME truncation `fork` seeded the child's `last_render_len` with: both route through
    `_complete_prefix_len`. Recomputing it any other way makes the two numbers independent, and
    an ingest whose live list is shorter than the last render raises `IngestTailUnderflow`.
    """
    if spec is None:
        return store.new_session(agent_id="main"), None
    validate(store, spec)
    source_session = session_store.main_session_id(store)
    session_id = store.fork(source_session, at_message_id=spec.branch_message_id)
    prefix = session_store.hydrate(store, session_id, role="send")
    visible = framework_view(prefix)
    if len(visible) != len(prefix):
        # Re-seed to what the framework will report, because that is what `ingest` compares
        # against. `fork` set this to the store's row count, which is right for every other
        # reader and wrong for this one.
        store.set_last_render_len(session_id, len(visible))
    return session_id, visible
