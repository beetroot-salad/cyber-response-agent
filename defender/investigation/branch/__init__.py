"""Resume a finished investigation from one of its own messages, in a sibling world."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic_ai.messages import ModelResponse, RetryPromptPart, ToolCallPart, ToolReturnPart

from defender import _clock
from defender._io import (
    guarded_mkdir,
    read_jsonl_rows,
    read_text_soft,
    write_guarded,
)
from defender.records import Run, RunPaths, artifact_dir, artifact_file
from defender.knowledge import is_reserved_query_id

from defender.records import session_store
from ..run_state import RunState
from ._spec import (
    REFUSED_FOLDED_SESSION,
    REFUSED_NO_CAPTURE,
    REFUSED_NO_FORK_SNAPSHOT,
    REFUSED_NO_SOURCE_RUN,
    REFUSED_NO_TOOL_CALL,
    REFUSED_NOT_A_MESSAGE,
    REFUSED_NOTHING_OPEN,
    REFUSED_OFF_MAIN_PATH,
    REFUSED_RETRY_STREAK,
    REFUSED_SOURCE_CHANGED,
    REFUSED_UNOPENED,
    REFUSED_UNREADABLE_FORK_SNAPSHOT,
    BranchError,
    BranchSpec,
    open_source_store,
    source_store_if_any,
    store_factory_for,
)
from . import _snapshot
from ._snapshot import ForkSnapshot, SnapshotWriter, snapshot_at
from ._frontier import (
    MainRead,
    _DISPATCH_TOOL,
    carried_retries,
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
    point_time,
    fence_count_at,
    leads_at,
    main_session,
    session_for_run,
    source_session,
)
from defender.records.formats import (
    holds_content,
    inherited_artifact_names,
    lead_dirs,
    refuse_seeded_run_dir,
)
from ._seed import restore_run_folder, source_alert


def validate(store: Any, spec: BranchSpec, *, source_run: Run,
             require_capture: bool = True) -> None:
    """Refuse a branch point that cannot carry a sibling world (`admitted_snapshot`'s
    refusals); a check only, so it hands nothing back."""
    admitted_snapshot(store, spec, source_run=source_run, require_capture=require_capture)


def admitted_points(main: MainRead, run_dir: Path, row_ids: list[int], *,
                    source_run: Run) -> list[tuple[int, BranchError | None]]:
    """Each of `row_ids` with the refusal a sibling's own admission gives it there, or `None`
    when admitted: `admitted_snapshot` at its default, the capture required, as every sibling
    run applies it, over the source's main session read once (`main`) for all of them."""
    answers: list[tuple[int, BranchError | None]] = []
    for row_id in row_ids:
        try:
            as_of = point_time(main, run_dir, row_id)
            _admitted_on(main, BranchSpec(source_run_dir=run_dir, branch_message_id=row_id, as_of=as_of),
                         source_run=source_run, require_capture=True)
        except BranchError as refused:
            answers.append((row_id, refused))
        else:
            answers.append((row_id, None))
    return answers


def admitted_snapshot(store: Any, spec: BranchSpec, *, source_run: Run,
                      require_capture: bool = True) -> _snapshot.ForkSnapshot:
    """Refuse a branch point that cannot carry a sibling world, and return the fork snapshot
    an arm taken there restores."""
    _refuse_not_a_message(spec)
    return _admitted_on(MainRead(store, Path(spec.source_run_dir), source_run=source_run), spec,
                        source_run=source_run, require_capture=require_capture)


def _refuse_not_a_message(spec: BranchSpec) -> None:
    # `BranchSpec` already refused a non-int at construction.
    if spec.branch_message_id <= 0:
        raise BranchError(
            f"branch_message_id must be a real message, got {spec.branch_message_id} — "
            "message 0 precedes every payload, so no world can contradict the prefix", kind=REFUSED_NOT_A_MESSAGE)


def _admitted_on(main: MainRead, spec: BranchSpec, *, source_run: Run,  # noqa: C901 — one refusal per rule, in order
                 require_capture: bool) -> _snapshot.ForkSnapshot:
    """`admitted_snapshot` over the source's main session already read (`main`)."""
    from defender.skills.invlang.frontier import frontier_from_text
    from defender.skills.invlang.parser import scan_fences

    store = main.store
    run_dir = Path(spec.source_run_dir)
    _refuse_not_a_message(spec)

    # On MAIN's path, not merely a number: an id past the tip or from a gather session would
    # fork a sub-agent's transcript as MAIN's.
    session, path = main.session, main.path
    if spec.branch_message_id not in path:
        raise BranchError(
            f"message {spec.branch_message_id} is not on the source run's MAIN path "
            f"({len(path)} row(s), {path[0] if path else '-'}..{path[-1] if path else '-'}) — "
            "a branch point has to be a message this run's own main session actually holds", kind=REFUSED_OFF_MAIN_PATH)

    # A folded session stays unbranchable (D4): the fold reparents the frontier onto the
    # lineage root, so the path no longer says which turns the run's requests were. Refused
    # before `store.fork`, which commits and cannot be undone.
    if session_store.displaced_tip(store, session) is not None:
        raise BranchError(
            f"{run_dir}'s main session has been folded (compaction displaced tip "
            f"{session_store.displaced_tip(store, session)}) — a folded session cannot be "
            "branched: the fold displaced turns the arm's history would have to hold. Branch "
            "an uncompacted run", kind=REFUSED_FOLDED_SESSION)

    upto = main.prefix[: path.index(spec.branch_message_id) + 1]
    branch_response = upto[-1]
    if not isinstance(branch_response, ModelResponse) or not any(
            isinstance(p, ToolCallPart) for p in branch_response.parts):
        raise BranchError(
            f"message {spec.branch_message_id} is a "
            f"{'text-only response' if isinstance(branch_response, ModelResponse) else 'request'}"
            " — a branch point is a MAIN response that called tools, so the arm resumes by "
            "running those calls against its own world and is handed no message of its own", kind=REFUSED_NO_TOOL_CALL)

    carried = carried_retries(upto[:-1])
    if carried:
        raise BranchError(
            f"message {spec.branch_message_id} is inside a retry streak ({carried} carried) — "
            "the framework's per-tool retry counts cannot be seeded into an arm, so it would "
            "take that step differently. Branch at a response no tool carries a retry into", kind=REFUSED_RETRY_STREAK)

    snapshot = _snapshot.load(store, session, _snapshot.request_count(upto))
    if snapshot is None:
        raise BranchError(
            f"{run_dir} recorded no fork snapshot for message {spec.branch_message_id} — a run "
            "recorded before fork snapshots existed (or one whose snapshot was not recorded) "
            "cannot be branched: nothing says what it held when that response arrived", kind=REFUSED_NO_FORK_SNAPSHOT)

    # The clock, checked here because only the store knows this branch point's moment.
    snapshot.verify(source_run)
    _refuse_bad_as_of(spec, snapshot.fork_time)
    # Sentinel rows (`∅.`-prefixed ids) never reached a system, so they are not evidence.
    rows = [row for row in snapshot.captured_rows(source_run)
            if not is_reserved_query_id(str(row.get("query_id", "")))]
    if not rows and require_capture:
        raise BranchError(
            f"{run_dir} captured no query that reached a system by message "
            f"{spec.branch_message_id} — a sibling world would be consistent with an empty "
            "prefix by construction, which is the generated-world design, not a branch", kind=REFUSED_NO_CAPTURE)

    document = snapshot.document if snapshot.document is not None else ""
    fences = len(scan_fences(document).bodies)
    open_state = frontier_from_text(document)
    if not open_state.slots and not open_state.contracts:
        raise BranchError(
            f"nothing is open in the frontier at message {spec.branch_message_id} "
            f"({fences} fence(s): 0 slots, 0 contracts, {len(open_state.held)} held) — there "
            "is no question there for a pair of worlds to divide", kind=REFUSED_NOTHING_OPEN)
    return snapshot


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
    store: Any, spec: BranchSpec | None, run: Run, *, case_id: str, session_id: str,
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
            run, case_id=recorded, store_path=store.path, session_id=session_id)
    except BaseException:
        if spec is not None:
            stamp_dead_fork(store, session_id)
        raise
    return recorded


def open_main_session(
    store: Any, spec: BranchSpec | None, run_state: RunState, *, run: Run, source_run: Run | None = None,
) -> tuple[str, list | None]:
    """MAIN's session for this run and the history it starts from."""
    if spec is None:
        return store.new_session(agent_id="main"), None
    try:
        # Every refusal before the fork: `store.fork` commits, and each retried refusal after
        # it would leave another orphan session in the source database.
        if source_run is None:
            raise BranchError("a resumed run requires its source Run", kind=REFUSED_NO_SOURCE_RUN)
        snapshot = admitted_snapshot(store, spec, source_run=source_run)
        refuse_seeded_run_dir(run_state.run_dir)
        session = source_session(store, spec, source_run=source_run)
        session_id = store.fork(session, at_message_id=spec.branch_message_id)
        try:
            prefix = session_store.hydrate(store, session_id, role="send")
            visible = framework_view(prefix)
            if len(visible) != len(prefix):
                # Re-seed to the framework's count, which `ingest` compares against. Inside the
                # guard so a failure here still stamps the orphan.
                store.set_last_render_len(session_id, len(visible))
            restore_run_folder(snapshot, run_state, run=run, source_run=source_run)
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
            f"not be opened: {type(e).__name__}: {e}", kind=REFUSED_UNOPENED) from e
    return session_id, visible


#: Re-exports; each name's home is the module it is imported from.
__all__ = [
    "Any",
    "REFUSED_FOLDED_SESSION",
    "REFUSED_NO_CAPTURE",
    "REFUSED_NO_FORK_SNAPSHOT",
    "REFUSED_NO_SOURCE_RUN",
    "REFUSED_NO_TOOL_CALL",
    "REFUSED_NOT_A_MESSAGE",
    "REFUSED_NOTHING_OPEN",
    "REFUSED_OFF_MAIN_PATH",
    "REFUSED_RETRY_STREAK",
    "REFUSED_SOURCE_CHANGED",
    "REFUSED_UNOPENED",
    "REFUSED_UNREADABLE_FORK_SNAPSHOT",
    "BranchError",
    "BranchSpec",
    "ForkSnapshot",
    "MainRead",
    "SnapshotWriter",
    "Counter",
    "Path",
    "RetryPromptPart",
    "RunPaths",
    "ToolCallPart",
    "ToolReturnPart",
    "_DISPATCH_TOOL",
    "inherited_artifact_names",
    "lead_dirs",
    "_appended_text",
    "_as_of_of",
    "_call_args",
    "_clock",
    "_drop_refused_dispatch",
    "holds_content",
    "_known_leads",
    "_lead_of",
    "_prefix_stamps",
    "_refuse_bad_as_of",
    "_utc",
    "artifact_dir",
    "artifact_file",
    "admitted_points",
    "point_time",
    "attach_case_pointer",
    "branch_point_time",
    "carried_retries",
    "contextlib",
    "dataclass",
    "datetime",
    "fence_count_at",
    "framework_view",
    "guarded_mkdir",
    "is_reserved_query_id",
    "json",
    "leads_at",
    "main_session",
    "open_main_session",
    "open_source_store",
    "source_store_if_any",
    "read_jsonl_rows",
    "read_text_soft",
    "refuse_seeded_run_dir",
    "restore_run_folder",
    "source_alert",
    "session_for_run",
    "session_store",
    "source_session",
    "snapshot_at",
    "sqlite3",
    "stamp_dead_fork",
    "store_factory_for",
    "timedelta",
    "validate",
    "admitted_snapshot",
    "write_guarded",
]
