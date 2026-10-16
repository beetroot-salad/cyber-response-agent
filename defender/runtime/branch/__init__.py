"""Resume a finished investigation from one of its own messages, in a sibling world.

The turn-N branch forks a real run once its evidence is in hand and continues it under a world
that differs from the one it ran in. This package owns which message may be branched from and
where the forked session lives.

A branch point is a MAIN response that called tools (#1255 D1). `session_store.fork()` charges
the child for the whole prefix through it, and `hydrate(role="send")` hands that same list back
(the fork point is kept even though its calls are unanswered), so the resumed framework runs
those calls first and its next request is the one a natural run would have sent.

  * `_spec`     — what a branch request is, and opening the store it reads from.
  * `_frontier` — reading the source run: its sessions, what the clock said at the branch
                     point, the retry counts the framework carried into it.
  * `_snapshot` — the fork snapshot: what the run held when each MAIN response arrived, and
                     restoring an arm's folder from it.
  * `_seed`     — writing the sibling's folder from the snapshot.

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

from pydantic_ai.messages import ModelResponse, RetryPromptPart, ToolCallPart, ToolReturnPart

from defender import _clock
from defender._io import (
    guarded_mkdir,
    read_jsonl_rows,
    read_text_soft,
    write_guarded,
)
from defender.run_repository import Run, RunPaths, artifact_dir, artifact_file
from defender._query_rules import is_reserved_query_id

from .. import session_store
from ..run_state import RunState
from ._spec import (
    BranchError,
    BranchSpec,
    open_source_store,
    source_store_if_any,
    store_factory_for,
)
from . import _snapshot
from ._snapshot import ForkSnapshot, SnapshotWriter, snapshot_at
from ._frontier import (
    _DISPATCH_TOOL,
    carried_retries,
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
    restore_run_folder,
    source_alert,
    seed_investigation,
)


def validate(store: Any, spec: BranchSpec, *, source_run: Run,
             require_capture: bool = True) -> _snapshot.ForkSnapshot:
    """Refuse a branch point that cannot carry a sibling world, and return the fork snapshot
    an arm taken there restores.

    A branch point is a MAIN response that called tools whose answers are not yet in the
    history (#1255 D1): the arm resumes with no new message, and its framework runs those calls
    against the arm's world. Admitted only when, beyond being on MAIN's own path in a session
    that was never folded (D4):

    - no tool carries a retry count into it (rev 5 C1): the framework's counts cannot be seeded;
    - the run recorded a fork snapshot for it (N4: a run recorded before the snapshot existed
      cannot be branched), and the source still holds what that snapshot recorded;
    - the clock the spec carries is this branch point's;
    - the capture as it stood there is non-empty (branching before any capture makes every
      world trivially consistent). The launcher passes `require_capture=False`: an empty
      capture is pre-flight's to record as a `refused` episode (#1224, M05=A);
    - something is open in the frontier the snapshot's document holds — `slots` or
      `contracts`, not `not is_empty()`, which also counts settled `held` facts.

    Every legality check reads the source as of the branch point's snapshot, never the whole
    finished source (rev 5 C7).
    """
    from defender.skills.invlang.frontier import frontier_at
    from defender.skills.invlang.parser import scan_fences

    run_dir = Path(spec.source_run_dir)
    # `BranchSpec` already refused a non-int at construction.
    if spec.branch_message_id <= 0:
        raise BranchError(
            f"branch_message_id must be a real message, got {spec.branch_message_id} — "
            "message 0 precedes every payload, so no world can contradict the prefix")

    # On MAIN's path, not merely a number: an id past the tip or from a gather session would
    # fork a sub-agent's transcript as MAIN's.
    session = source_session(store, spec, source_run=source_run)
    path = session_store.path_row_ids(store, session)
    if spec.branch_message_id not in path:
        raise BranchError(
            f"message {spec.branch_message_id} is not on the source run's MAIN path "
            f"({len(path)} row(s), {path[0] if path else '-'}..{path[-1] if path else '-'}) — "
            "a branch point has to be a message this run's own main session actually holds")

    # A folded session stays unbranchable (D4): the fold reparents the frontier onto the
    # lineage root, so the path no longer says which turns the run's requests were. Refused
    # before `store.fork`, which commits and cannot be undone.
    if session_store.displaced_tip(store, session) is not None:
        raise BranchError(
            f"{run_dir}'s main session has been folded (compaction displaced tip "
            f"{session_store.displaced_tip(store, session)}) — a folded session cannot be "
            "branched: the fold displaced turns the arm's history would have to hold. Branch "
            "an uncompacted run")

    prefix = session_store.hydrate(store, session, role="analysis")
    upto = prefix[: path.index(spec.branch_message_id) + 1]
    branch_response = upto[-1]
    if not isinstance(branch_response, ModelResponse) or not any(
            isinstance(p, ToolCallPart) for p in branch_response.parts):
        raise BranchError(
            f"message {spec.branch_message_id} is a "
            f"{'text-only response' if isinstance(branch_response, ModelResponse) else 'request'}"
            " — a branch point is a MAIN response that called tools, so the arm resumes by "
            "running those calls against its own world and is handed no message of its own")

    carried = carried_retries(upto[:-1])
    if carried:
        raise BranchError(
            f"message {spec.branch_message_id} is inside a retry streak ({carried} carried) — "
            "the framework's per-tool retry counts cannot be seeded into an arm, so it would "
            "take that step differently. Branch at a response no tool carries a retry into")

    snapshot = _snapshot.load(store, session, _snapshot.request_count(upto))
    if snapshot is None:
        raise BranchError(
            f"{run_dir} recorded no fork snapshot for message {spec.branch_message_id} — a run "
            "recorded before fork snapshots existed (or one whose snapshot was not recorded) "
            "cannot be branched: nothing says what it held when that response arrived")

    # The clock, checked here because only the store knows this branch point's moment.
    _refuse_bad_as_of(spec, _as_of_of(upto, run_dir, spec.branch_message_id))

    snapshot.verify(source_run)
    # Sentinel rows (`∅.`-prefixed ids) never reached a system, so they are not evidence.
    rows = [row for row in snapshot.captured_rows(source_run)
            if not is_reserved_query_id(str(row.get("query_id", "")))]
    if not rows and require_capture:
        raise BranchError(
            f"{run_dir} captured no query that reached a system by message "
            f"{spec.branch_message_id} — a sibling world would be consistent with an empty "
            "prefix by construction, which is the generated-world design, not a branch")

    document = snapshot.document if snapshot.document is not None else ""
    fences = len(scan_fences(document).bodies)
    open_state = frontier_at(document, fences).frontier
    if not open_state.slots and not open_state.contracts:
        raise BranchError(
            f"nothing is open in the frontier at message {spec.branch_message_id} "
            f"({fences} fence(s): 0 slots, 0 contracts, {len(open_state.held)} held) — there "
            "is no question there for a pair of worlds to divide")
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
    """MAIN's session for this run and the history it starts from.

    The one place the fresh/resumed choice is made. A fresh run gets a new session and `None`.
    A resume is validated (every refusal before the fork), forks at the branch point, and
    returns the prefix through the branch response via `hydrate(role="send")` — the list
    `fork` charged the child for — so the framework runs that response's calls first. The
    run folder is restored to what the source held at the branch point
    (`ForkSnapshot.restore_files`); the driver starts the run's counters, review gate, caps
    and request count from the same snapshot (`snapshot_at`).

    Other faults (e.g. a pydantic `ValidationError` on a payload from another framework
    version, or the private `framework_view` import disappearing) are converted to
    `BranchError` so the driver's store-setup handler catches them.
    """
    if spec is None:
        return store.new_session(agent_id="main"), None
    try:
        # Every refusal before the fork: `store.fork` commits, and each retried refusal after
        # it would leave another orphan session in the source database.
        if source_run is None:
            raise BranchError("a resumed run requires its source Run")
        snapshot = validate(store, spec, source_run=source_run)
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
            f"not be opened: {type(e).__name__}: {e}") from e
    return session_id, visible


#: Re-exports; each name's home is the module it is imported from.
__all__ = [
    "Any",
    "BranchError",
    "BranchSpec",
    "ForkSnapshot",
    "SnapshotWriter",
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
    "carried_retries",
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
    "source_store_if_any",
    "read_jsonl_rows",
    "read_text_soft",
    "refuse_seeded_run_dir",
    "restore_run_folder",
    "source_alert",
    "seed_investigation",
    "session_for_run",
    "session_store",
    "source_session",
    "snapshot_at",
    "sqlite3",
    "stamp_dead_fork",
    "store_factory_for",
    "timedelta",
    "validate",
    "write_guarded",
]
