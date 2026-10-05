"""Resume a finished investigation from one of its own messages, in a sibling world.

The turn-N branch forks a real run once its evidence is in hand and continues it under a world
that differs from the one it ran in. This package owns which message may be branched from and
where the forked session lives.

`session_store.fork()` seeds the child's `last_render_len` to the send-role length of the
inherited prefix. The caller must hand that prefix back as `message_history` (a fresh
`agent.iter` starts empty, and `selection.ingest` would underflow); `open_main_session` returns
it via `hydrate(role="send")`, which truncates through the same `_complete_prefix_len` as `fork`.

  * `_spec`     — what a branch request is, and opening the store it reads from.
  * `_frontier` — reading the source run: where the fences end, which leads existed,
                     what the clock said at the branch point.
  * `_seed`     — writing the sibling: the inherited prefix, evidence and lead dirs.

`validate` refuses a branch that would not be a faithful fork.
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
from defender.run_repository import RunPaths, artifact_dir, artifact_file
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
    _lead_dirs,
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
    _inherited,
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

    Beyond the branch point being a complete message on MAIN's path with a matching clock, a
    world is only meaningfully "consistent with the evidence" when:

    - the capture is non-empty (branching at message 0 makes every world trivially consistent);
    - something is open in the frontier — `slots` or `contracts`, not `not is_empty()`, which
      also counts settled `held` facts and would admit a finished investigation;
    - the frontier was not snapped: the session's appends account for more fences than the
      document holds (truncated or rewritten off the append path), so the answer would be the
      finished document's frontier.
    """
    run_dir = Path(spec.source_run_dir)
    # `BranchSpec` already refused a non-int at construction.
    if spec.branch_message_id <= 0:
        raise BranchError(
            f"branch_message_id must be a real message, got {spec.branch_message_id} — "
            "message 0 precedes every payload, so no world can contradict the prefix")

    # On MAIN's path, not merely a number: an id past the tip or from a gather session would
    # miscount fences, and `fork` would inherit a sub-agent's transcript.
    session = source_session(store, spec)
    path = session_store.path_row_ids(store, session)
    if spec.branch_message_id not in path:
        raise BranchError(
            f"message {spec.branch_message_id} is not on the source run's MAIN path "
            f"({len(path)} row(s), {path[0] if path else '-'}..{path[-1] if path else '-'}) — "
            "a branch point has to be a message this run's own main session actually holds")

    # A complete pair: a response with an unanswered tool call would become the fork's head,
    # and providers reject a `tool_use` with no result (a 400 on the first request). Same
    # `_complete_prefix_len` rule `fork` and `hydrate` use.
    prefix = session_store.hydrate(store, session, role="analysis")
    upto = prefix[: path.index(spec.branch_message_id) + 1]
    if session_store._complete_prefix_len(upto) != len(upto):
        raise BranchError(
            f"message {spec.branch_message_id} is a response whose tool call is still "
            "unanswered — the fork would inherit a dangling tool call as its head, and the "
            "first request of the resumed run would carry a `tool_use` with no result. Branch "
            "at the tool RETURN that answers it instead")

    # The clock, checked here because only the store knows this branch point's moment.
    _refuse_bad_as_of(spec, _as_of_of(upto, run_dir, spec.branch_message_id))

    # A folded session cannot say what it dispatched: the fold hides the gather pairs, so
    # `leads_at` would silently let the sibling inherit every lead. Refused before `store.fork`,
    # which commits and cannot be undone.
    if session_store.displaced_tip(store, session) is not None:
        raise BranchError(
            f"{run_dir}'s main session has been folded (compaction displaced tip "
            f"{session_store.displaced_tip(store, session)}) — a fold reparents the frontier "
            "onto the lineage root, so the gather dispatches it displaced are reachable from "
            "nothing and no branch point on it can say which leads the run held. Branch an "
            "uncompacted run, or fork before the fold")

    # Sentinel rows (`∅.`-prefixed ids) never reached a system, so they are not evidence.
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
    # Snapped first: a clamped answer is the terminal frontier, which would otherwise be misreported
    # as "nothing open".
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
    """The prefix as the framework will hold it, which is not always as the store holds it.

    `pydantic_ai` merges adjacent same-role messages in a handed-in history (the store produces
    that shape: the correlation lead's synthesized request sits next to a tool-return request).
    `fork` and `hydrate` count store rows, so `last_render_len` must be re-seeded to this count
    or ingest breaks. Uses the framework's own private function so the rule cannot drift.
    """
    from pydantic_ai._agent_graph import _clean_message_history

    return _clean_message_history(list(prefix))


def stamp_dead_fork(store: Any, session_id: str | None) -> None:
    """Mark a forked session that no run will ever drive.

    `store.fork` commits and sessions cannot be deleted, so stamping `truncated_by` makes the
    orphan legible as finished. Best-effort and silent: callers are already unwinding a fault it
    must not replace.
    """
    if session_id is None:
        return
    with contextlib.suppress(Exception):
        store.set_truncated_by(session_id, session_store.TRUNCATED_BY_STORE)


def attach_case_pointer(
    store: Any, spec: BranchSpec | None, run_dir: Path, *, case_id: str, session_id: str,
) -> str:
    """Write the run's case pointer, and stamp the fork if that write is what fails.

    The case id comes from the store, not the caller's minted uuid: a resume joins the source's
    case, and a wrong id would fail `open_source_store`'s derive-and-compare check, so a branch
    could not be taken from a branch. Returns the recorded id so the run summary agrees.

    The session id is the run's own; a sibling shares the source's database, so the lineage
    root would name the source's transcript.
    """
    # Truthiness: `open_store_for_read` handles carry an empty `case_id`.
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

    The one place the fresh/resumed choice is made. A fresh run gets a new session and `None`.
    A resume forks, returns the prefix via `hydrate(role="send")` (the same truncation `fork`
    seeded `last_render_len` with), and seeds `investigation.md` into the new run dir so the
    inherited messages never point at a missing file.

    Other faults (e.g. a pydantic `ValidationError` on a payload from another framework
    version, or the private `framework_view` import disappearing) are converted to
    `BranchError` so the driver's store-setup handler catches them.
    """
    if spec is None:
        return store.new_session(agent_id="main"), None
    try:
        # Every refusal before the fork: `store.fork` commits, and each retried refusal after
        # it would leave another orphan session in the source database.
        validate(store, spec)
        refuse_seeded_run_dir(run_dir)
        session = source_session(store, spec)
        session_id = store.fork(session, at_message_id=spec.branch_message_id)
        try:
            prefix = session_store.hydrate(store, session_id, role="send")
            visible = framework_view(prefix)
            if len(visible) != len(prefix):
                # Re-seed to the framework's count, which `ingest` compares against. Inside the
                # guard so a failure here still stamps the orphan.
                store.set_last_render_len(session_id, len(visible))
            seed_investigation(store, spec, run_dir)
        except BaseException:
            # The fork cannot be rolled back; stamp it so it reads as ended, not mid-flight.
            stamp_dead_fork(store, session_id)
            raise
    except (BranchError, session_store.StoreError, sqlite3.Error, OSError):
        # Already handled by the driver; re-raise so `exit_reason` names the real type.
        raise
    except Exception as e:
        raise BranchError(
            f"the resume of {spec.source_run_dir} at message {spec.branch_message_id} could "
            f"not be opened: {type(e).__name__}: {e}") from e
    return session_id, visible


#: Re-exports; each name's home is the module it is imported from.
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
    "_inherited",
    "_lead_dirs",
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
