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

The turn-N branch: forking a run from a message in an earlier one.

Split into three modules when this file reached 1197 lines:

  * `_spec`     — what a branch request IS, and opening the store it reads from.
  * `_frontier` — reading the source run: where the fences end, which leads existed,
                     what the clock said at the branch point.
  * `_seed`     — writing the sibling: the inherited prefix, evidence and lead dirs.

`validate` below is what refuses a branch that would not be a faithful fork, and it is
the reason the two halves above stay separable.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart

from defender import _clock
from defender._io import (
    guarded_mkdir,
    read_jsonl_rows,
    read_text_soft,
    write_guarded,
)
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender.scripts.gather_tools.record_query import is_reserved_query_id

from .. import session_store
from ._spec import (
    BranchError,
    BranchSpec,
    open_source_store,
    store_factory_for,
)
from ._frontier import (
    _DISPATCH_TOOL,
    _LEAD_DIRS,
    _appended_text,
    _as_of_of,
    _call_args,
    _drop_refused_dispatch,
    _known_leads,
    _lead_of,
    _prefix_stamps,
    _refuse_bad_as_of,
    _utc,
    branch_point_time,
    fence_count_at,
    frontier_at_branch,
    leads_at,
    main_session,
    session_for_run,
    source_session,
)
from ._seed import (
    _INHERITED,
    _copy_artifact,
    _holds_content,
    _inherit_evidence,
    _inherit_lead_dir,
    _not_a_plain_file,
    refuse_seeded_run_dir,
    seed_investigation,
)


def validate(store: Any, spec: BranchSpec) -> None:
    """Refuse a branch point that cannot carry a sibling world.

    TWO preconditions about the evidence, and both are about the same thing — a world is only
    meaningfully "consistent with the evidence" when there IS evidence and there IS something
    unresolved — plus one about the branch point's own SHAPE (a complete pair; see below).

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
    has been handed the one state that keys nothing". `snapped` here means the appends the session
    records landed MORE fences than the document on disk holds, so the two halves disagree about
    what was written, the message-to-fence mapping is not trustworthy for this run, and the
    answer would be the FINISHED document's frontier — the one a branch must never read.

    (A refused `append_block` is NOT how that happens, though an earlier spelling of this
    paragraph said so: `_tool_append_block` refuses through `ModelRetry`, which the framework
    records as a `RetryPromptPart`, and `fence_count_at` drops those without counting. A
    document truncated or rewritten outside the append path is what remains.)
    """
    run_dir = Path(spec.source_run_dir)
    # THE TYPE FIRST, because `BranchSpec` is a plain frozen dataclass and its `int` annotation
    # is not a runtime check. A spec built from untyped input — a CLI flag, a JSON world file —
    # carries `"59"`, and the comparison below then raises `TypeError`, which is not a
    # `BranchError` and so escapes the driver's store-setup handler entirely: the sqlite
    # connection stays open and `llm_requests.jsonl` stays registered in `observe._ACTIVE_PATHS`,
    # which is the exact exit that handler was widened to close. `bool` is excluded because it
    # is an `int` that names no message.
    if not isinstance(spec.branch_message_id, int) or isinstance(spec.branch_message_id, bool):
        raise BranchError(
            f"branch_message_id must be an int, got {spec.branch_message_id!r} — a branch point "
            "is a message id this run's own store holds, not a spelling of one")
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
    session = source_session(store, spec)
    path = session_store.path_row_ids(store, session)
    if spec.branch_message_id not in path:
        raise BranchError(
            f"message {spec.branch_message_id} is not on the source run's MAIN path "
            f"({len(path)} row(s), {path[0] if path else '-'}..{path[-1] if path else '-'}) — "
            "a branch point has to be a message this run's own main session actually holds")

    # A COMPLETE PAIR, and not merely a message on the path. `fork` seeds the child's
    # `last_render_len` from `_complete_prefix_len`, so a branch point that is a `ModelResponse`
    # with an unanswered tool call is hidden from the FIRST `message_history` — and then the
    # fork's HEAD is still that row, so `ingest` parents the continuation onto it and the very
    # next `hydrate(role="send")` ends on a `ModelRequest` and hands the dangling `tool_use`
    # straight back. Every provider rejects a tool call with no matching result, so the resumed
    # run dies on request 1 with a 400 that names nothing about branching. Refused here, through
    # the SAME `_complete_prefix_len` `fork` and `hydrate` truncate with, so there is one rule.
    prefix = session_store.hydrate(store, session, role="analysis")
    upto = prefix[: path.index(spec.branch_message_id) + 1]
    if session_store._complete_prefix_len(upto) != len(upto):
        raise BranchError(
            f"message {spec.branch_message_id} is a response whose tool call is still "
            "unanswered — the fork would inherit a dangling tool call as its head, and the "
            "first request of the resumed run would carry a `tool_use` with no result. Branch "
            "at the tool RETURN that answers it instead")

    # THE CLOCK, checked here rather than at construction because `BranchSpec` is a frozen
    # dataclass whose annotations are not runtime checks, and because the only thing that can
    # say whether a moment is THIS branch point's is the store. Cheap: the derivation reuses
    # the slice already hydrated above rather than re-reading.
    _refuse_bad_as_of(spec, _as_of_of(upto, run_dir, spec.branch_message_id))

    # A SESSION THAT HAS FOLDED CANNOT SAY WHAT IT DISPATCHED, and the failure is silent in the
    # unsafe direction. `selection._fold_impl` parents the frontier onto the lineage ROOT, so
    # `path_row_ids` collapses to `[root, frontier]` and every `gather` call/return pair the
    # fold displaced is reachable from nothing. `leads_at` then finds no dispatch at all,
    # `dispatched` is empty, and `_known_leads(run_dir) - dispatched` degenerates to the WHOLE
    # census — so the sibling inherits every lead the source ever gathered, including the ones
    # it gathered after the fork, while `leads_at` returns a perfectly clean-looking answer.
    # That is verbatim the leak evidence truncation exists to close, restored by a config flag
    # (`DEFENDER_COMPACTION`) with nothing red.
    #
    # REFUSED HERE, before `store.fork`, for the reason every refusal in this module is: a
    # `fork` commits its own transaction and nothing can undo one, so a truncation that
    # discovered this later would leave an orphan child session per attempt. Under-counting is
    # this seam's safe direction and over-counting is not, so a census it cannot compute is a
    # refusal rather than a guess.
    if session_store.displaced_tip(store, session) is not None:
        raise BranchError(
            f"{run_dir}'s main session has been folded (compaction displaced tip "
            f"{session_store.displaced_tip(store, session)}) — a fold reparents the frontier "
            "onto the lineage root, so the gather dispatches it displaced are reachable from "
            "nothing and no branch point on it can say which leads the run held. Branch an "
            "uncompacted run, or fork before the fold")

    # SENTINELS ARE NOT CAPTURES. A `∅.`-prefixed `query_id` is a writer-only record of a call
    # that never reached a system of record — a refused repeat, a param-schema rejection, a
    # failed reducer shim — and `lead_repository.joined` splits exactly those onto
    # `JoinedLead.sentinels` so `.queries` means only what the defender ran. This precondition
    # asks the `.queries` question ("is there evidence a world could contradict?"), so it has to
    # read the `.queries` set: a run whose whole table is refusals has rows and no evidence, and
    # counting them admits the branch this raise exists to refuse. The predicate is
    # `record_query`'s own, never a second spelling of the prefix.
    rows = [
        row for row in read_jsonl_rows(RunPaths(run_dir).executed_queries)
        if not is_reserved_query_id(str(row.get("query_id", "")))
    ]
    if not rows:
        raise BranchError(
            f"{run_dir} captured no query that reached a system — a sibling world would be "
            "consistent with an empty prefix by construction, which is the generated-world "
            "design, not a branch")

    frontier = frontier_at_branch(store, spec)
    # SNAPPED FIRST. A clamped index answers the TERMINAL frontier, which is the document state
    # with everything settled and nothing open — so asking "is anything open?" of it reports
    # "branched too late" for a run whose real fault is that the message-to-fence mapping is not
    # trustworthy at all. Diagnosing the clamp before reading its answer is what keeps the two
    # refusals naming their own cause.
    if frontier.snapped:
        raise BranchError(
            f"message {spec.branch_message_id} maps to fence {frontier.requested}, but "
            f"{RunPaths(run_dir).investigation} holds only {frontier.total} — the answer was "
            f"snapped to the terminal frontier, which is the one state a branch point must "
            "not be read at")
    open_state = frontier.frontier
    if not open_state.slots and not open_state.contracts:
        raise BranchError(
            f"nothing is open in the frontier at message {spec.branch_message_id} "
            f"(fence {frontier.n} of {frontier.total}: 0 slots, 0 contracts, "
            f"{len(open_state.held)} held) — there is no question there for a pair of worlds "
            "to divide")


def framework_view(prefix: list) -> list:
    """The prefix as the FRAMEWORK will hold it, which is not always as the store holds it.

    `pydantic_ai` normalises a handed-in `message_history` before the first request, and part
    of that is MERGING ADJACENT SAME-ROLE messages — requests with requests, and responses
    with responses; both shapes are measured in `test_920_framework_contract.py`. The store deliberately produces exactly that
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


def stamp_dead_fork(store: Any, session_id: str | None) -> None:
    """Mark a forked session that no run will ever drive.

    `store.fork` COMMITS, and this store exposes no way to delete a session — so a resume that
    fails after the fork leaves a child in the source's database that nothing distinguishes
    from a sibling still running. Stamped with the same `truncated_by` every other interrupted
    session carries, it is at least legible as finished.

    Best-effort and silent about its own failure on purpose: every caller is already unwinding
    a fault it must not replace (`_record_beside` in the estate seam is the same rule).
    """
    if session_id is None:
        return
    with contextlib.suppress(Exception):
        store.set_truncated_by(session_id, session_store.TRUNCATED_BY_STORE)


def attach_case_pointer(
    store: Any, spec: BranchSpec | None, run_dir: Path, *, case_id: str, session_id: str,
) -> str:
    """Write the run's case pointer, and stamp the fork if that write is what fails.

    Returns the case id it RECORDED, which is the run's real one — the caller's minted uuid is
    a fresh run's and names no session in a resumed run's database. Handed back rather than
    re-derived at the call site so the pointer and the run summary cannot disagree about which
    case a run joined: the summary reporting the uuid is the same mismatch this function's
    third paragraph says "was not cosmetic", left in the other artifact.

    THE CASE ID COMES OFF THE STORE, not from the caller's minted one. On a fresh run they are
    the same string; on a resume the minted uuid names no session in the database the pointer
    points at, because `fork` inherits its parent row's `case_id`. Recorded wrong, the pointer
    fails `open_source_store`'s derive-and-compare check — so a branch could never be taken
    FROM a branch — and it fails it while naming the opposite cause.

    THE SESSION ID is the run's own, which is what a reader needs when the store holds more
    than one run. A sibling forks into the source's database, so resolving run_dir -> store ->
    root-of-lineage renders the SOURCE's transcript for it.

    Here rather than in the composition root because this is the LAST step that can fail after
    a committed fork, and the compensation for that belongs beside the fork it compensates for.
    """
    # TRUTHINESS, not `is not None`: `open_store_for_read` builds a handle whose `case_id` is
    # the EMPTY string, and recording that would write a pointer naming no case at all.
    recorded = getattr(store, "case_id", None) or case_id
    try:
        session_store.write_case_pointer(
            run_dir, case_id=recorded, store_path=store.path, session_id=session_id)
    except BaseException:
        if spec is not None:
            stamp_dead_fork(store, session_id)
        raise
    return recorded


def open_main_session(
    store: Any, spec: BranchSpec | None, run_dir: Path,
) -> tuple[str, list | None]:
    """MAIN's session for this run, the history it starts from, and the document that history
    refers to.

    THE one place the fresh/resumed choice is made, so the driver's composition root stays a
    straight line and the two cases cannot drift apart. A fresh run gets a new session and
    `None` — `agent.iter`'s own empty list is exactly right when nothing is inherited.

    THE DOCUMENT IS PART OF THE OPEN, not a step after it. A resume inherits the source's
    messages into a FRESH run dir, and `investigation.md` lives in the run dir — so a caller
    that opened the session and forgot the document would hand the model coordinates into a
    file that does not exist, which is the one failure `seed_investigation` exists to remove.
    Seeded here, the two cannot be done apart.

    A resume forks and hands back the prefix through `hydrate(role="send")`, because that is
    the SAME truncation `fork` seeded the child's `last_render_len` with: both route through
    `_complete_prefix_len`. Recomputing it any other way makes the two numbers independent, and
    an ingest whose live list is shorter than the last render raises `IngestTailUnderflow`.

    EVERY OTHER FAULT HERE IS STILL A SETUP FAULT, so it leaves as one. A resume is the only
    caller that validates, hydrates and forks INSIDE `run_investigation`'s store-setup `try`,
    and that handler names classes — `sqlite3.Error`, `StoreError`, `BranchError`, `OSError`.
    The work below raises outside them: `_message_from_payload` validates a stored payload
    through pydantic, which answers `ValidationError` on a row written by another framework
    version (`open_store_for_read`'s own docstring names schema skew as a live residue), and
    `framework_view` imports a private framework symbol that a minor upgrade can remove. Either
    would unwind `run_investigation` entirely, leaving the sqlite connection open AND
    `llm_requests.jsonl` registered in `observe._ACTIVE_PATHS` — so the next sibling in an
    in-process sweep can never reopen it. Converted here rather than by widening the driver's
    tuple, because this is the frame that knows the work was a resume's.
    """
    if spec is None:
        return store.new_session(agent_id="main"), None
    try:
        # EVERY REFUSAL THIS MODULE OWNS, BEFORE THE FORK. `store.fork` commits its own
        # transaction and nothing here can undo one, so a refusal raised after it leaves a
        # child session in the SOURCE database with no run behind it — and the refusals below
        # are the repeatable kind (a retried resume, a dir a partial attempt already seeded),
        # so every retry would add another.
        validate(store, spec)
        refuse_seeded_run_dir(run_dir)
        session = source_session(store, spec)
        session_id = store.fork(session, at_message_id=spec.branch_message_id)
        try:
            prefix = session_store.hydrate(store, session_id, role="send")
            visible = framework_view(prefix)
            if len(visible) != len(prefix):
                # Re-seed to what the framework will report, because that is what `ingest`
                # compares against. `fork` set this to the store's row count, which is right
                # for every other reader and wrong for this one.
                #
                # INSIDE the guard, not after it: this is a store write on an already-committed
                # fork, so a fault here leaves the orphan the stamp below exists to mark — and
                # a class the driver's store-setup handler does not name escapes
                # `run_investigation` entirely, leaving the connection open and
                # `llm_requests.jsonl` registered in `observe._ACTIVE_PATHS`.
                store.set_last_render_len(session_id, len(visible))
            seed_investigation(store, spec, run_dir)
        except BaseException:
            # WHAT REMAINS AFTER THE FORK cannot be rolled back into the store either, so the
            # orphan is STAMPED through the column every other interrupted session already
            # uses. It then reads as a session that ended rather than one still live —
            # `ends_on_complete_pair` answers False for it, and a reader counting a run's
            # children can tell a dead fork from a sibling that is mid-flight. Best-effort:
            # this is a failure path, and a stamp that fails must not replace the fault.
            stamp_dead_fork(store, session_id)
            raise
    except (BranchError, session_store.StoreError, sqlite3.Error, OSError):
        # Already a class the driver's store-setup handler names; re-raised untouched so the
        # run's `exit_reason` still carries the type that actually failed.
        raise
    except Exception as e:
        raise BranchError(
            f"the resume of {spec.source_run_dir} at message {spec.branch_message_id} could "
            f"not be opened: {type(e).__name__}: {e}") from e
    return session_id, visible


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "Any",
    "BranchError",
    "BranchSpec",
    "Counter",
    "Path",
    "RetryPromptPart",
    "RunPaths",
    "ToolCallPart",
    "ToolReturnPart",
    "_DISPATCH_TOOL",
    "_INHERITED",
    "_LEAD_DIRS",
    "_appended_text",
    "_as_of_of",
    "_call_args",
    "_clock",
    "_copy_artifact",
    "_drop_refused_dispatch",
    "_holds_content",
    "_inherit_evidence",
    "_inherit_lead_dir",
    "_known_leads",
    "_lead_of",
    "_not_a_plain_file",
    "_prefix_stamps",
    "_refuse_bad_as_of",
    "_utc",
    "artifact_dir",
    "artifact_file",
    "attach_case_pointer",
    "branch_point_time",
    "contextlib",
    "dataclass",
    "datetime",
    "fence_count_at",
    "framework_view",
    "frontier_at_branch",
    "guarded_mkdir",
    "is_reserved_query_id",
    "json",
    "leads_at",
    "main_session",
    "open_main_session",
    "open_source_store",
    "read_jsonl_rows",
    "read_text_soft",
    "refuse_seeded_run_dir",
    "seed_investigation",
    "session_for_run",
    "session_store",
    "source_session",
    "sqlite3",
    "stamp_dead_fork",
    "store_factory_for",
    "timedelta",
    "validate",
    "write_guarded",
]
