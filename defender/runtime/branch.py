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

from defender._io import read_jsonl_rows, read_text_soft
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
    # ONE read of the pointer, and every way it can be malformed lands as `BranchError` — the
    # class the driver's store-setup handler catches. A bare `KeyError`/`JSONDecodeError` from
    # here escapes that handler and takes the process down with the wire log still registered.
    try:
        pointer = json.loads(
            (run_dir / session_store.POINTER_FILENAME).read_text(encoding="utf-8"))
        recorded = Path(pointer["store_path"])
        case_id = pointer["case_id"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BranchError(
            f"{run_dir} carries no readable case pointer "
            f"({session_store.POINTER_FILENAME}): {e!r}") from e
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

    ONE ROW PER FENCE, and it is the tool RETURN. `session_store._tool_name` stamps the name on
    BOTH halves of a round-trip — the `ModelResponse` carrying the `ToolCallPart` and the
    `ModelRequest` carrying the `ToolReturnPart` — so counting every row that names
    `append_block` doubles the count, and past the document's midpoint `frontier_at` then snaps
    to the FINISHED document, which is the one state a branch point must never be read at. The
    return is the half that agrees with the prefix: `hydrate(role="send")` truncates a trailing
    response whose tool call is unresolved, so the fence is counted exactly when the prefix
    carries it.

    A MEMBERSHIP test, not equality: `_tool_name` comma-joins every distinct tool a message
    names ("One response legitimately carries several tool calls"), so `== "append_block"`
    silently counts a turn that batched the fence with any other tool as no fence at all.
    """
    ids = session_store.path_row_ids(store, session_id)
    rows = session_store.hydrate(store, session_id, role="actor")
    return sum(
        1 for row_id, row in zip(ids, rows, strict=True)
        if row_id <= branch_message_id and row.get("kind") == "request"
        and "append_block" in (row.get("tool_name") or "").split(",")
    )


def main_session(store: Any) -> str:
    """The source run's MAIN session, or a `BranchError`.

    `main_session_id` raises a bare `ValueError` on zero or several roots — a store that is not
    the one the branch point lives in, which `open_source_store`'s docstring names as the fault
    it surfaces far away. Re-raised as this module's own class so it reaches the driver's
    store-setup handler rather than unwinding the process.
    """
    try:
        return session_store.main_session_id(store)
    except ValueError as e:
        raise BranchError(f"the source store holds no single root 'main' session: {e}") from e


def frontier_at_branch(store: Any, spec: BranchSpec):
    """The investigation's open state as it stood at the branch point.

    `frontier_at` is imported HERE, not at module scope, and that is load-bearing rather than
    untidy. `driver.py` does `from . import branch` at module level, so hoisting this pulls
    `skills.invlang.frontier` and ten sibling invlang modules into the import graph of every
    process that imports the driver — measured with `-X importtime` at 109ms cumulative for
    that subtree, paid by every investigation, every gather subagent and every e2e child,
    when only a resume ever reaches this function.
    """
    from defender.skills.invlang.frontier import frontier_at

    text, _ = read_text_soft(RunPaths(Path(spec.source_run_dir)).investigation)
    # A run that authored no document reads as the empty frontier, which is what `validate`
    # refuses on — the same answer `frontier_at` gives a fence-less document.
    return frontier_at(
        text if text is not None else "",
        fence_count_at(store, main_session(store), spec.branch_message_id))


def validate(store: Any, spec: BranchSpec) -> None:
    """Refuse a branch point that cannot carry a sibling world.

    TWO preconditions, and both are about the same thing — a world is only meaningfully
    "consistent with the evidence" when there IS evidence and there IS something unresolved.

    **A non-empty capture.** At message 0 the adapters have returned nothing, so every proposed
    world is trivially consistent with the prefix and the captured base guards nothing. That is
    the generated-world design the redesign rejected, reached by branching too early rather
    than by choosing it.

    **SOMETHING OPEN in the frontier.** `frontier_at` answers the empty frontier for a
    fence-less document, and nothing open is nothing to discriminate — the pair would have no
    question to divide.

    Open means `slots` or `contracts`, NOT `Frontier.is_empty()`. That predicate also counts
    `held`, which is what the document has already SETTLED: a finished investigation carries
    ~15 held facts against zero open slots, so `is_empty()` reads it as a perfectly good branch
    point when it is the exact case this precondition exists to refuse — branched too late,
    with every question already answered. `is_empty()` is false only for a document with no
    populated cells at all, which is the same set the fence-less arm already covers.

    **A frontier that was not SNAPPED.** `frontier_at` clamps an out-of-range fence index and
    says so rather than raising, and its own docstring names why that must not pass silently:
    "a curator who asks for block 12 of a 4-block document and is handed the terminal frontier
    has been handed the one state that keys nothing". `snapped` here means the store counted
    more landed fences than the document holds — a refused `append_block` still leaves a tool
    return in the session — so the message-to-fence mapping is not trustworthy for this run,
    and the answer would be the FINISHED document's frontier, the one a branch must never read.
    """
    run_dir = Path(spec.source_run_dir)
    if spec.branch_message_id <= 0:
        raise BranchError(
            f"branch_message_id must be a real message, got {spec.branch_message_id} — "
            "message 0 precedes every payload, so no world can contradict the prefix")

    # ON MAIN'S PATH, and not merely a number. `fence_count_at` scores rows with
    # `row_id <= branch_message_id`, so an id past the tip reads as "every fence" and one
    # belonging to another session in the same case DB — a `gather:l-NNN` leg's row — reads as
    # "all of MAIN's fences so far". Neither is caught downstream: `fork` walks parents from
    # the id it is given regardless of session, so the foreign id yields a child whose prefix
    # is a SUB-AGENT's transcript while this function vouched for MAIN's document, and the
    # phantom id survives to `hydrate`, which fails far away with `UnresolvablePathElement`
    # after the run dir's pointer has already been written.
    path = session_store.path_row_ids(store, main_session(store))
    if spec.branch_message_id not in path:
        raise BranchError(
            f"message {spec.branch_message_id} is not on the source run's MAIN path "
            f"({len(path)} row(s), {path[0] if path else '-'}..{path[-1] if path else '-'}) — "
            "a branch point has to be a message this run's own main session actually holds")

    rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    if not rows:
        raise BranchError(
            f"{run_dir} captured no queries — a sibling world would be consistent with an "
            "empty prefix by construction, which is the generated-world design, not a branch")

    frontier = frontier_at_branch(store, spec)
    open_state = frontier.frontier
    if not open_state.slots and not open_state.contracts:
        raise BranchError(
            f"nothing is open in the frontier at message {spec.branch_message_id} "
            f"(fence {frontier.n} of {frontier.total}: 0 slots, 0 contracts, "
            f"{len(open_state.held)} held) — there is no question there for a pair of worlds "
            "to divide")
    if frontier.snapped:
        raise BranchError(
            f"message {spec.branch_message_id} maps to fence {frontier.requested}, but "
            f"{RunPaths(run_dir).investigation} holds only {frontier.total} — the answer was "
            f"snapped to the terminal frontier, which is the one state a branch point must "
            "not be read at")


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
    source_session = main_session(store)
    session_id = store.fork(source_session, at_message_id=spec.branch_message_id)
    prefix = session_store.hydrate(store, session_id, role="send")
    visible = framework_view(prefix)
    if len(visible) != len(prefix):
        # Re-seed to what the framework will report, because that is what `ingest` compares
        # against. `fork` set this to the store's row count, which is right for every other
        # reader and wrong for this one.
        store.set_last_render_len(session_id, len(visible))
    return session_id, visible
