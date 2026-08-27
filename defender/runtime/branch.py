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

    `as_of` is the branch point's own moment — the time the sibling is resuming INTO. It is
    REQUIRED rather than defaulted, because the one wrong answer is the silent one: a spec that
    fell back to "now" would let every sibling stamp its payloads with the afternoon it
    executed, which is exactly the defect the field exists to remove, arriving through the
    field itself. `branch_point_time` derives it from the source store; `validate` refuses a
    spec whose value disagrees with that derivation, so a hand-written or copy-pasted spec
    cannot carry another branch point's clock into this episode.
    """

    source_run_dir: Path
    branch_message_id: int
    continuation_prompt: str
    as_of: datetime


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

    Both sides are RESOLVED before they are compared, because `Path.__eq__` compares spellings
    and the two sides are spelled by different callers. The writer recorded whatever
    `runs_base` its run was handed; this reads whatever `source_run_dir` the branch was handed.
    A caller that normalises — `Path(x).resolve()`, a relative path, a `..` component, or the
    symlinked `/tmp` the default runs base lives under on macOS (`open_store`'s own comment
    names that one) — otherwise gets this refusal for the RIGHT database, with a message
    naming the opposite cause.
    """
    # RESOLVED FIRST, because `runs_base` is derived from `.parent` and `Path("run-x").parent`
    # is `Path(".")` — a one-component relative run dir would derive the store under the
    # PROCESS's cwd and be refused with a message naming the opposite cause. Resolving after
    # the derivation, as the comparison below does, cannot recover the parent that was lost.
    run_dir = Path(run_dir).resolve()
    # ONE read of the pointer, and every way it can be malformed lands as `BranchError` — the
    # class the driver's store-setup handler catches. A bare `KeyError`/`JSONDecodeError` from
    # here escapes that handler and takes the process down with the wire log still registered.
    # `store_path_for` is INSIDE it for the same reason: it raises `InvalidCaseId`, which is a
    # bare `ValueError` and no kind of `StoreError`, so a pointer carrying a `case_id` that is
    # not a well-formed one took exactly the exit this block exists to close.
    try:
        pointer = json.loads(
            (run_dir / session_store.POINTER_FILENAME).read_text(encoding="utf-8"))
        recorded = Path(pointer["store_path"]).resolve()
        case_id = pointer["case_id"]
        derived = session_store.store_path_for(case_id, runs_base=run_dir.parent).resolve()
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BranchError(
            f"{run_dir} carries no readable case pointer "
            f"({session_store.POINTER_FILENAME}): {e!r}") from e
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


def fence_count_at(
    store: Any, session_id: str, branch_message_id: int, document: str,
) -> int:
    """How many invlang fences the document held at `branch_message_id`.

    `frontier_at` indexes the DOCUMENT's own ````invlang` blocks, so this has to answer in that
    unit or it silently addresses the wrong state. THREE things break the tempting shortcut of
    counting `append_block` calls, all of them live, and all of them under-count — the silent
    direction, because `FrontierAt.snapped` fires only when a caller asks PAST the end, so an
    under-count branches the sibling at a frontier the run had already moved past and reports
    nothing wrong.

    - ONE CALL, SEVERAL FENCES. The text is one string and may carry any number of blocks. The
      e2e harness's own `_split_at_fences` cuts a golden into fewer chunks than it has fences
      whenever the two numbers disagree, which is not a test artifact — nothing asks a model
      for one block per call either.
    - ONE TURN, SEVERAL CALLS. `tools.py` sets `sequential=True`, which orders two calls inside
      one response rather than preventing them, and nothing sets `parallel_tool_calls=False`.
      This is also why the `actor` projection cannot answer it: `session_store._tool_name`
      publishes every DISTINCT tool a message names, comma-joined, so it cannot say "twice".
    - NOT EVERY FENCE CAME FROM AN APPEND. `lead_zero` writes lead-0's declaring `:L findings`
      block into `investigation.md` itself, before the model's first turn, so a count derived
      from the session alone is short by that block on EVERY real run — and a seed sliced by
      it would drop the model's last landed fence.

    So the document is the unit and the session says only WHEN. The blocks no append accounts
    for (`total - overall`) are what was already on disk when the model started writing, and
    they are present at every branch point; the appends carry the rest, attributed to the
    message that returned them.

    THE TOOL RETURN is what makes a call count, and the CALL carries the text, so the two
    halves join on `tool_call_id`. The return is the half that agrees with the prefix —
    `hydrate(role="send")` truncates a trailing response whose tool call is unresolved — so a
    fence counts exactly when the prefix carries the write that landed it.

    THE CLAMP IS WHAT KEEPS `snapped` MEANINGFUL. A document holding FEWER fences than the
    appends say were written is a document that was truncated or rewritten, and there the
    unaccounted-for term is negative; clamped at 0, the running count can still run past
    `total` and `frontier_at` reports the disagreement instead of quietly answering from a
    state neither half describes.
    """
    from defender.skills.invlang.parser import INVLANG_FENCE_RE

    ids = session_store.path_row_ids(store, session_id)
    messages = session_store.hydrate(store, session_id, role="analysis")
    pending: dict[str, str] = {}
    through = overall = 0
    for row_id, message in zip(ids, messages, strict=True):
        for part in getattr(message, "parts", []):
            if getattr(part, "tool_name", None) != "append_block":
                continue
            if isinstance(part, ToolCallPart):
                pending[part.tool_call_id] = _appended_text(part)
            elif isinstance(part, RetryPromptPart):
                # A REFUSAL LANDS NOTHING, and it is not a return. `_tool_append_block` turns
                # all five of its refusals into `ModelRetry`, which the framework records as a
                # `RetryPromptPart` — so the call's text would otherwise sit in `pending`
                # forever, and a provider that reuses a `tool_call_id` after a refusal would
                # have the next return pop the refused text instead of its own.
                pending.pop(part.tool_call_id, None)
            elif isinstance(part, ToolReturnPart):
                landed = len(INVLANG_FENCE_RE.findall(pending.pop(part.tool_call_id, "")))
                overall += landed
                through += landed if row_id <= branch_message_id else 0
    return max(0, len(INVLANG_FENCE_RE.findall(document)) - overall) + through


def _appended_text(part: Any) -> str:
    """The `text` an `append_block` call carries, however the framework spelled its args.

    `ToolCallPart.args` is a dict on the ordinary path and a JSON STRING when the provider
    hands back unparsed arguments — both shapes reach the store, and a reader that knew only
    the first would score every one of the other's calls as zero fences. Anything else is
    read as no text rather than raised on: this counts what landed, and a call whose args
    cannot be read is one whose fences cannot be attributed either way.
    """
    return _call_args(part).get("text", "")


def _call_args(part: Any) -> dict:
    """A `ToolCallPart`'s arguments as a dict, however the framework spelled them.

    `args` is a dict on the ordinary path and a JSON STRING when the provider hands back
    unparsed arguments — both shapes reach the store, and a reader that knew only the first
    would silently score every one of the other's calls as carrying nothing. Anything else
    reads as no arguments rather than raising: this caller COUNTS what landed, and a call whose
    args cannot be read is one whose effect cannot be attributed either way.

    A FENCE-COUNTING reader, and only that. `leads_at` walks the same shapes for a lead id and
    goes through `session_store._lead_id_from_args` instead — the store's own extractor, which
    the `gather_boundary` view answers with, and which resolves a duplicate JSON key
    first-wins where a bare `loads` takes the last. Two rules over one hostile-text boundary is
    a divergence nothing can see, so the id question has exactly one answer and this function
    is not it.
    """
    args = getattr(part, "args", None)
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return {}
    return args if isinstance(args, dict) else {}


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


def source_session(store: Any, spec: BranchSpec) -> str:
    """The SOURCE RUN's OWN main session — which is the root of the lineage only sometimes.

    `main_session_id` answers the ROOT, and `fork` sets the child's `parent_session_id`, so a
    sibling is never it. Asked of a source run that is ITSELF a sibling, the root is the run it
    branched from: `validate` then refuses every branch point in the source's own turns as "not
    on the source run's MAIN path", and accepts one the source never held — after which `fork`
    inherits the GRANDPARENT's transcript while `seed_investigation` and `_inherit_evidence`
    seed the sibling from the source's document and evidence, and `fence_count_at` scores one
    run's appends against another run's file.

    The pointer is what closes it, and this PR is what put the field there: `attach_case_pointer`
    records the session the run owns, and `resolve_session_id` answers `None` for every run
    written before it existed and for every fresh run — where the two coincide and the root is
    right. The same fallback `visualize_run` resolves its transcript through, spelled once here
    so the branch seam and the renderer cannot disagree about which session is a run's own.
    """
    return session_for_run(store, Path(spec.source_run_dir))


def session_for_run(store: Any, run_dir: Path) -> str:
    """`source_session`'s answer, asked of a RUN DIR rather than of a spec.

    Split out because T0 has to be derived BEFORE a `BranchSpec` exists — the spec carries
    `as_of`, so anything that computes it cannot already hold one. Same rule, one spelling: a
    second "which session does this run own" would be free to disagree with the branch seam
    about exactly the question `attach_case_pointer` was added to settle.
    """
    try:
        recorded = session_store.resolve_session_id(Path(run_dir))
    except (OSError, ValueError):
        # A run dir with no readable pointer is one `open_source_store` has already refused on
        # the path that opens a store; reached any other way, the root is the honest fallback
        # and the refusals below still name what they find.
        recorded = None
    return recorded if recorded is not None else main_session(store)


def branch_point_time(store: Any, run_dir: Path, branch_message_id: int) -> datetime:
    """The moment the branch point was written — the clock a sibling resumes INTO.

    Read off the STORE rather than the run dir's mtimes or the wall clock, because the store is
    the only thing that knows when each message landed. `ModelRequest` and `ModelResponse` both
    carry a `timestamp`, and the store round-trips it through pydantic-ai's own type adapter, so
    the value is the framework's rather than one this module mints.

    THE MAXIMUM over the prefix, not the branch row's own stamp. The rows are written in path
    order but a resumed lineage can interleave, and a T0 EARLIER than some message the sibling
    inherits would put the sibling before its own evidence — the one relationship the whole
    design rests on. The max is the honest reading of "everything in the prefix has happened".

    TRUNCATED TO WHOLE SECONDS, at the derivation and nowhere else. `_clock.Z_SECONDS` drops
    sub-second precision, so a microsecond-bearing T0 formats to a string that no longer
    round-trips to it — and `validate`'s cross-check would then reject the very spec this
    function produced, for a difference no reader can see.
    """
    session = session_for_run(store, run_dir)
    path = session_store.path_row_ids(store, session)
    if branch_message_id not in path:
        raise BranchError(
            f"message {branch_message_id} is not on {run_dir}'s own main session, so it has no "
            "branch-point time — the id has to be one this run's main path actually holds")
    prefix = session_store.hydrate(store, session, role="analysis")
    return _as_of_of(prefix[: path.index(branch_message_id) + 1], run_dir, branch_message_id)


def _as_of_of(prefix: list, run_dir: Path, branch_message_id: int) -> datetime:
    """T0 from an already-hydrated prefix slice.

    The rule lives here alone so `branch_point_time` (which hydrates) and `validate` (which
    already has the slice in hand) cannot compute it two ways — the failure that would produce
    is a spec this module derived and then refused on its own cross-check.

    PARTS COUNT, NOT ONLY MESSAGES, and that is a correction rather than a widening.
    `ModelResponse.timestamp` is `default_factory=now_utc` but `ModelRequest.timestamp` is
    `datetime | None = None` — the framework fills it when the request is SENT, so a request
    that was appended and never sent carries none. That is exactly the shape `validate` steers
    an operator into: it refuses a dangling tool call and tells them to branch at the tool
    RETURN, which is a `ModelRequest`, and a run that ended there never sent it. Reading
    messages alone, T0 then silently fell back to the PRECEDING `ModelResponse` — the moment
    the model asked, not the moment the evidence landed, which for a gather lead is minutes
    earlier — and put the sibling before its own evidence, the one relationship the maximum is
    here to preserve. `ToolReturnPart.timestamp` is stamped when the return is built, so the
    part carries the moment the message forgot.

    NORMALISED BEFORE THE MAXIMUM, not after. `max` over a list mixing naive and aware
    datetimes raises `TypeError: can't compare offset-naive and offset-aware datetimes` — not a
    `BranchError`, so it escapes `run_investigation`'s store-setup handler entirely, leaving the
    sqlite connection open and `llm_requests.jsonl` registered in `observe._ACTIVE_PATHS`. A
    repair applied to the winner cannot save a comparison that already raised.
    """
    stamps = [
        _utc(at) for at in _prefix_stamps(prefix) if isinstance(at, datetime)
    ]
    if not stamps:
        # A prefix carrying no timestamp on any message OR any part is not what this function
        # was pointed at. Falling back to the wall clock here would hand back "now" under the
        # name of a branch point, which is the defect `as_of` exists to remove — arriving
        # through its own derivation, and invisible afterwards.
        raise BranchError(
            f"no message at or before {branch_message_id} in {run_dir} carries a timestamp, so "
            "the branch point has no moment to resume into")
    return max(stamps).replace(microsecond=0)


def _prefix_stamps(prefix: list):
    """Every moment the prefix carries, message-level and part-level alike."""
    for message in prefix:
        yield getattr(message, "timestamp", None)
        for part in getattr(message, "parts", ()):
            yield getattr(part, "timestamp", None)


def _utc(at: datetime) -> datetime:
    """`at` as an aware UTC moment, reading a NAIVE value as UTC.

    `_clock.as_utc`'s rule and NOT a second copy of it: T0 is normalised here at the
    DERIVATION and again inside `_clock.z_seconds` at every FORMATTING, and `_refuse_bad_as_of`
    compares the two for exact equality — so two spellings that ever part make this module
    refuse the very spec it just derived.
    """
    return _clock.as_utc(at)


def _refuse_bad_as_of(spec: BranchSpec, derived: datetime) -> None:
    """Refuse a spec whose clock is not this branch point's.

    Two failures, one raise-site. A NAIVE or non-UTC `as_of` formats a trailing `Z` that lies by
    the host's offset, and nothing downstream can tell that from a correct stamp. A value that
    disagrees with `branch_point_time` is a spec carrying ANOTHER branch point's clock — the
    copy-paste case — and it lands as an episode whose siblings agree with each other and with
    nothing else, which no comparison can detect from the inside.
    """
    at = spec.as_of
    if not isinstance(at, datetime):
        raise BranchError(
            f"as_of must be a datetime, got {at!r} — a branch point without a moment cannot "
            "pin the clock its siblings resume into")
    if at.tzinfo is None or at.utcoffset() != timedelta(0):
        raise BranchError(
            f"as_of must be an aware UTC datetime, got {at!r} (offset {at.utcoffset()!r}) — a "
            "naive or offset value formats a trailing `Z` that lies by that offset, and every "
            "payload stamped from it is then wrong by the same amount with nothing to show it")
    if at != derived:
        raise BranchError(
            f"as_of is {at.isoformat()} but message {spec.branch_message_id} of "
            f"{spec.source_run_dir} was written at {derived.isoformat()} — a spec carrying "
            "another branch point's clock yields an episode whose siblings agree with each "
            "other and with nothing else")


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
    document = text if text is not None else ""
    return frontier_at(
        document,
        fence_count_at(store, source_session(store, spec), spec.branch_message_id, document))


#: The tool whose call/return pair is the only join from a message id to a run's evidence.
#:
#: THE NAME pydantic-ai REGISTERS, which is the function's: `@main_agent.tool async def gather`
#: in `tools_gather`. Spelled wrong, this matches no part in any message — `dispatched` stays
#: empty, the lead-0 set difference below degenerates to the WHOLE table, and every sibling
#: inherits every lead its source ever gathered while `leads_at` reports a clean answer.
_DISPATCH_TOOL = "gather"


def _drop_refused_dispatch(
    pending: dict[str, str], dispatches: Counter[str], tool_call_id: str,
) -> None:
    """Remove this refused call's census contribution without erasing another call."""
    refused = pending.pop(tool_call_id, None)
    if refused is None:
        return
    dispatches[refused] -= 1
    if dispatches[refused] <= 0:
        del dispatches[refused]


def leads_at(store: Any, session_id: str, branch_message_id: int, run_dir: Path) -> set[str]:
    """Which gather leads the run held by `branch_message_id`.

    THE LEAD IS THE JOIN, because there is no other. `append_query_row` writes thirteen frozen
    keys and not one of them is a timestamp or a message id, so a query row cannot be dated
    against the session directly. What it does carry is `lead_id`, and every lead enters through
    a `gather` call/return pair in MAIN's own transcript — so the session dates the
    lead, and the lead dates its rows.

    THE RETURN is what makes a lead count, mirroring `fence_count_at` for the same reason: the
    return is the half the prefix agrees with, so a lead counts exactly when the inherited
    history shows the model learning it exists. A `RetryPromptPart` drops the claim, because a
    refused dispatch claims nothing and its `tool_call_id` may be reused.

    UNDER-COUNTING IS THE SILENT DIRECTION AND IT IS CORRECT. A dispatch whose return had not
    landed by the branch point is dropped — and it should be: the prefix does not carry that
    return either, so the resumed model has no idea the lead exists and would be reasoning over
    evidence its own history cannot cite. Do not "fix" this to count the call.

    LEADS NO DISPATCH ACCOUNTS FOR ARE KEPT, always. Lead-0 writes its rows before the model's
    first turn, so no dispatch in any session explains them and they are present at every branch
    point. Derived as a set difference against the table rather than by naming the reserved ids,
    for the same reason `fence_count_at` does not hardcode lead-0's fence: the ids are lead-0's
    business, and a copy here would be a second place to update when they change.

    The subtrahend is every lead an UNREFUSED dispatch named, not merely every lead that
    returned — see the comment at the call site. Those are different sets exactly when a run
    ended with a dispatch outstanding, and taking the narrower one silently reclassifies that
    lead as lead-0's. A retry-refused call is removed again because it performed no work; this
    matters when it named a claim lead-0 had already placed in the run dir.

    AN UNFOLDED SESSION IS A PRECONDITION, and `validate` is where it is refused. A fold
    reparents the frontier onto the lineage root, so the dispatches it displaced are reachable
    from nothing, `dispatched` comes back empty and the set difference below degenerates to the
    whole census — the leak this function exists to close, wearing a clean answer. Checked
    there rather than here because a refusal after `store.fork` leaves an orphan child session.
    """
    ids = session_store.path_row_ids(store, session_id)
    messages = session_store.hydrate(store, session_id, role="analysis")
    pending: dict[str, str] = {}
    dispatches: Counter[str] = Counter()
    landed: set[str] = set()
    for row_id, message in zip(ids, messages, strict=True):
        for part in getattr(message, "parts", []):
            if getattr(part, "tool_name", None) != _DISPATCH_TOOL:
                continue
            if isinstance(part, ToolCallPart):
                # THE STORE's OWN EXTRACTOR, not a second one. `session_store._lead_id_from_args`
                # is what the `gather_boundary` view answers "which lead did this call name"
                # with, and it decodes a string `args` under `object_pairs_hook=_first_wins_pairs`
                # while a bare `json.loads` lets the LAST duplicate key win. Two rules over one
                # hostile-text boundary means the danger lens and this truncation can name
                # different leads for one dispatch — and a lead named only by the losing
                # spelling falls through the subtraction below as if lead-0 had written it, so
                # its whole evidence class is inherited by a sibling whose prefix never shows it.
                lead_id = session_store._lead_id_from_args(getattr(part, "args", None))
                if lead_id:
                    pending[part.tool_call_id] = lead_id
                    # EVERY LEAD A DISPATCH NAMED, whether or not it ever returned — unless a
                    # later RetryPrompt says the tool REFUSED that call. This census is
                    # subtracted below to find lead-0's, and the question it has to answer is
                    # "could this call have produced work?", not "did the model hear back?".
                    # Recorded on the RETURN instead, a lead dispatched and never answered — a
                    # run killed mid-gather, or a dispatch still in flight at the tip — is
                    # absent here, falls through the subtraction as if lead-0 had written it,
                    # and its evidence is inherited by every sibling whose prefix never shows
                    # it returning. That is the leak this function exists to close, arriving
                    # through its one fallback.
                    dispatches[lead_id] += 1
            elif isinstance(part, RetryPromptPart):
                # A retry prompt means the tool refused THIS call. Remove only that call's
                # contribution to the census: another accepted dispatch may legitimately name
                # the same lead, so a bare set.discard would erase both.
                _drop_refused_dispatch(pending, dispatches, part.tool_call_id)
            elif isinstance(part, ToolReturnPart):
                claimed = pending.pop(part.tool_call_id, None)
                if claimed is not None and row_id <= branch_message_id:
                    landed.add(claimed)
    return landed | (_known_leads(run_dir) - set(dispatches))


#: The per-lead evidence directories, in ONE place. `_known_leads` reads them for the census,
#: `_inherit_evidence` walks them for the copy, and `_INHERITED` below is derived from them for
#: the refusal — three readers of one fact, which is two too many to keep in step by hand.
_LEAD_DIRS = ("gather_raw", "gather_summaries")


def _known_leads(run_dir: Path) -> set[str]:
    """Every lead this run dir names, by any of the three artifacts that name one.

    THE TABLE IS NOT THE CENSUS. A lead is CLAIMED before it runs — `claim_lead` writes
    `gather_raw/{lead}.lead.json` as an exclusive create, and that sidecar is the reuse gate —
    so a lead can exist with no query row at all: it claimed, gathered nothing, and left only
    the claim. Lead-0's correlation lead is exactly that shape.

    Reading only the table therefore drops such a lead out of the set difference below, and the
    sibling inherits no claim for it — after which the resumed run re-dispatches an id its own
    prefix already used, `claim_lead` refuses the reuse, and turn-0 work is redone or lost. The
    sidecar is what `e2e/test_920_branch_resume` pins, and it is why the census is over
    ARTIFACTS rather than over rows.
    """
    paths = RunPaths(run_dir)
    known = {
        str(row.get("lead_id")) for row in read_jsonl_rows(paths.executed_queries)
        if row.get("lead_id")
    }
    for directory in (run_dir / name for name in _LEAD_DIRS):
        # `artifact_dir`, not `is_dir()`: this run dir is the box's rw bind, and a link planted
        # at a lead directory would otherwise contribute its TARGET's entry names to the set
        # that decides which leads a sibling inherits.
        if artifact_dir(directory):
            known |= {_lead_of(entry.name) for entry in directory.iterdir()}
    return {lead for lead in known if lead}


#: What a sibling inherits from the source RUN DIR, beside the document.
#:
#: The message prefix is full of absolute paths into the run dir that produced it — a gather
#: return names `gather_raw/{lead_id}/{seq}.json`, a lead claim names `{lead_id}.lead.json` —
#: and `permission.decide_read` roots the sibling at its OWN run dir, so every one of them is
#: denied to a model reading back its own history. The queries table rides along for the same
#: reason in reverse: `validate` refuses a branch whose source captured nothing, so the
#: sibling's evidence IS those rows, and a run dir that dropped them would report a run that
#: gathered nothing and then reasoned about it.
#:
#: DERIVED FROM `_LEAD_DIRS`, not spelled beside it. Three readers ask about the same set — the
#: census (`_known_leads`), the copy (`_inherit_evidence`) and this refusal — and while each
#: wrote its own tuple they could name different ones with nothing red: a fourth per-lead
#: artifact added HERE is then refused in a fresh sibling's run dir and never copied into it, so
#: the prefix names a path the sibling does not hold and `decide_read` denies the model its own
#: history — the exact failure this tuple exists to prevent, arriving through the tuple.
_INHERITED = ("executed_queries.jsonl", *_LEAD_DIRS)


def refuse_seeded_run_dir(run_dir: Path) -> None:
    """Refuse a sibling run dir that already holds inherited state.

    ASKED BEFORE THE FORK, which is the whole reason it is a function of its own. `store.fork`
    commits its own transaction and this module has no way to undo one, so a refusal raised
    after it leaves a child session in the SOURCE database with no run behind it — and a
    retried resume, which is exactly what hits this refusal, adds another every time.
    """
    run_dir = Path(run_dir)
    present = [name for name in (RunPaths(run_dir).investigation.name, *_INHERITED)
               if _holds_content(run_dir / name)]
    if present:
        raise BranchError(
            f"{run_dir} already holds {present} — a resumed run inherits those from its "
            "source, and a run dir that already carries them is not a fresh sibling: seeding "
            "over them would interleave two runs' evidence in artifacts that are append-only")


def _holds_content(path: Path) -> bool:
    """Does `path` hold anything a run put there?

    EXISTENCE IS NOT THE QUESTION. The run scaffolding creates `gather_raw/` for every run
    before a resume ever reaches this check, so an existence test refuses every branch — and
    an empty directory is what a fresh sibling is SUPPOSED to have. What a reused dir holds
    is content, and content is what seeding over would interleave.
    """
    # A SYMLINK IS CONTENT, whatever it points at, and it is refused HERE — before the fork —
    # rather than left to the copy. `_inherit_evidence` does route every directory through
    # `guarded_mkdir` and every file through `write_guarded` now, so a linked `gather_summaries`
    # would be refused there too; but that refusal lands AFTER `store.fork` has committed a
    # child session this module cannot undo, and this check is the whole reason
    # `refuse_seeded_run_dir` is a function of its own. An empty linked directory is otherwise
    # indistinguishable from the empty real one a fresh sibling is supposed to have, and the
    # scaffolding plants no links.
    if path.is_symlink():
        return True
    if path.is_dir():
        return any(path.iterdir())
    return path.is_file() and path.stat().st_size > 0


def seed_investigation(store: Any, spec: BranchSpec | None, run_dir: Path) -> int:
    """Write the sibling's `investigation.md`: the source's document as it stood at the branch.

    A FRESH RUN SEEDS NOTHING and says so with 0. The optional spec is `open_main_session`'s
    shape for the same reason: the fresh/resumed choice belongs to this module, and a driver
    that asked the question itself would answer it in two places that can drift.

    A resume joins the source's SESSION and gets a fresh RUN DIR, and the document is a run-dir
    artifact. Without this the two halves disagree from turn one: the inherited history says
    the model authored N fences, `_opening_prompt` hands it coordinates into that document, and
    `_tool_append_block` writes `deps.run_dir/"investigation.md"` — a file that does not exist.
    The model can then neither read back what its own history says it wrote (`decide_read` is
    rooted at the sibling's run dir, so the source's copy is denied) nor append to it without
    starting an empty one, and everything downstream reads the prefix-less result:
    `_check_append_only` has no blocks to conserve, `_frontier_recall` and `_fold_decision` see
    a document that never moved, and `review/projector.parse_investigation` reads the sibling's
    close against no belief history at all.

    TRUNCATED AT THE BRANCH POINT, never the whole file. The source ran ON past the fork and
    its later fences carry the conclusions this pair exists to NOT share — copying them whole
    would hand the sibling the answer and measure agreement with it. The cut is the same fence
    count `frontier_at_branch` reads the frontier at, so the seeded document and the frontier
    `validate` accepted are the same state by construction rather than by coincidence.

    SLICED, not rebuilt from fence bodies. `frontier_at` rebuilds a fence-only prefix because
    it only ever parses what it builds; this is the document the model will read back and
    append to, so the author's prose BETWEEN blocks is part of it. Slicing the original bytes
    is also what keeps the seed byte-identical to a prefix of the source, which is the property
    that makes the two documents comparable at all.

    The cut lands on a fence boundary, so prose the source wrote AFTER its last landed block
    does not come across. That is the honest edge of a fence-granular branch — `validate`
    accepted the frontier `frontier_at(text, n)` derives, and that derivation reads fences and
    ignores everything else, so the seed and the frontier describe the same state. It is also
    the safer side of the cut: the trailing prose on a real document is where a run writes the
    `## REPORT` section its disposition goes in, and a sibling inheriting the source's
    conclusion is handed the answer the pair exists to not share.

    Returns the fence count written, so the caller can record what the sibling started from.
    """
    if spec is None:
        return 0
    from defender.skills.invlang.parser import INVLANG_FENCE_RE

    target = RunPaths(Path(run_dir)).investigation
    refuse_seeded_run_dir(run_dir)
    source_text, _ = read_text_soft(RunPaths(Path(spec.source_run_dir)).investigation)
    text = source_text if source_text is not None else ""
    fences = fence_count_at(store, source_session(store, spec), spec.branch_message_id, text)
    bounds = list(INVLANG_FENCE_RE.finditer(text))
    if fences > len(bounds):
        # `validate` refuses a SNAPPED frontier, so the count is in range by the time this
        # runs. Restated here because the two reads are separated by a fork and this one
        # would otherwise slice silently short — a sibling starting from fewer fences than
        # its own history claims, which is the failure this function exists to remove.
        raise BranchError(
            f"{RunPaths(Path(spec.source_run_dir)).investigation} holds {len(bounds)} "
            f"fence(s) but the branch point maps to {fences} — the document and the session "
            "disagree about what had landed, and a seed cut from either is a guess")
    # `write_guarded`, not `write_text`: this writes into the shared run tree, and the seam
    # stages under an unpredictable name and `os.replace`s into place rather than opening the
    # target — so a planted symlink at the sibling's `investigation.md` is replaced instead of
    # followed. The same lane `_tool_append_block` writes this file through.
    write_guarded(target, text[: bounds[fences - 1].end()] if fences else "")
    _inherit_evidence(
        Path(spec.source_run_dir), Path(run_dir),
        leads_at(store, source_session(store, spec), spec.branch_message_id,
                 Path(spec.source_run_dir)))
    return fences


def _inherit_evidence(source_run_dir: Path, run_dir: Path, leads: set[str]) -> None:
    """Copy the evidence the inherited prefix REFERS TO into the sibling's run dir.

    COPIED, not shared or symlinked. The sibling appends to `executed_queries.jsonl` and writes
    new payload sidecars beside the old ones, and a link would put those writes into the source
    run's own record — corrupting the base of the very comparison the branch exists to produce.

    Absent is not an error. A source run that dispatched no gather has no `gather_raw/`, and
    `validate` has already refused the one absence that matters (an empty queries table), so
    everything else here is a directory that legitimately never existed.

    TRUNCATED TO `leads`, which is what the source run held AT THE BRANCH POINT. Copied
    whole, a sibling starts holding every payload the source went on to gather after the
    fork — evidence its own inherited history cannot cite, for leads it never dispatched,
    sitting in the table it reads as its own record of what it did. That is the source run's
    conclusion arriving through the back door, and it would flow straight into the verdict
    comparison the branch exists to produce.
    """
    # THE ALERT FIRST, and from the SEAM rather than from whichever launcher ran. It is the case
    # INPUT — not the source run's work — and every resumed history's first turn reads it, so a
    # sibling without one has no `read_file` target for a path its own prefix names. A launcher
    # that materialises the run dir has already put an identical copy here; rewriting it costs a
    # few hundred bytes and makes the guarantee the seam's, so `run_investigation(resume=…)`
    # holds it for every caller rather than only for the one CLI that remembers.
    #
    # NOT in `_INHERITED`: that tuple is what `refuse_seeded_run_dir` reads, and an alert is
    # exactly what a freshly materialised sibling legitimately already holds — listing it there
    # would refuse every sibling a launcher prepared.
    alert = RunPaths(source_run_dir).alert
    if alert.exists() or alert.is_symlink():
        if not artifact_file(alert):
            raise BranchError(
                f"{alert} is not a plain file — the alert is the case input both siblings "
                f"investigate, and one that is {_not_a_plain_file(alert)} is not the source "
                "run's own")
        # BYTES, for `_copy_artifact`'s reason: `materialize_run_dir` puts this file here with
        # `shutil.copy`, and a decode/re-encode round trip is a second spelling of the case
        # input that only agrees with the first while the alert happens to be valid UTF-8.
        write_guarded(RunPaths(run_dir).alert, alert.read_bytes())

    queries = RunPaths(source_run_dir).executed_queries
    if queries.exists() or queries.is_symlink():
        # REFUSED, NOT SKIPPED. `artifact_file` is an `lstat` check, so a symlink wearing the
        # table's own name fails it — and skipping there would seed a sibling with NO evidence
        # at all, which every downstream reader sees as a run that gathered nothing rather than
        # as a run whose evidence was refused. `validate` has already proved the source captured
        # something, so an unreadable table here is a fault, not an absence.
        if not artifact_file(queries):
            raise BranchError(
                f"{queries} is not a plain file — following a link at the queries table's own "
                "name would seed the sibling's evidence from outside the source run")
        rows = [row for row in read_jsonl_rows(queries) if str(row.get("lead_id", "")) in leads]
        write_guarded(
            RunPaths(run_dir).executed_queries,
            # NOT MARKED `lint-jsonl-io: ok`: `lint_unsafe_jsonl_io` flags a `json.dumps(...) +
            # "\n"` write to a handle opened in APPEND mode, and this is a whole-file rewrite
            # through `write_guarded`'s `replace` lane — out of that gate's scope rather than a
            # sanctioned exception to it. A marker here would pre-silence the site for the day
            # someone converts this seed to an append, which is the one drift the gate exists
            # to catch.
            "".join(json.dumps(row) + "\n" for row in rows))
    for name in _LEAD_DIRS:
        _inherit_lead_dir(source_run_dir / name, run_dir / name, leads, run_dir)


def _inherit_lead_dir(src: Path, dst: Path, leads: set[str], run_dir: Path) -> None:
    """Copy the entries of one per-lead directory that belong to `leads`.

    PER ENTRY, THROUGH THE GUARDED LANE, rather than `shutil.copytree`. Truncation needs
    per-entry selection anyway, and copying entry by entry is what lets each one face
    `artifact_file`/`artifact_dir` first — an `lstat` check, so a SYMLINK wearing an artifact's
    name is refused rather than having its target's bytes copied into the sibling under that
    name. The run dir is the box's rw bind and model-written bash writes into it, so a planted
    link at an expected payload name is a real shape rather than a theoretical one; `copytree`
    followed them without a word.

    A REFUSAL IS LOUD. Skipping one silently reads downstream as a lead that gathered nothing,
    which is indistinguishable from a lead the model never dispatched — and this whole function
    exists to make the sibling's evidence say exactly what the prefix can cite.
    """
    if not src.exists():
        # A source run that dispatched no gather has no such directory, and `validate` has
        # already refused the one absence that matters (an empty queries table).
        return
    if not artifact_dir(src):
        raise BranchError(
            f"{src} is not a plain directory — a sibling's evidence is copied out of it, and "
            "following a link here would seed the run from outside the source's own tree")
    # THE DESTINATION IS MADE THROUGH THE GUARDED LANE, not by `write_guarded`'s own parents —
    # it has none: `replace` mode stages beside the target and `os.replace`s in, so a missing
    # parent is a `FileNotFoundError` on the staged name rather than a created directory.
    # `copytree` used to do this implicitly, which is exactly why it was easy to drop when the
    # copy became per-entry. ONCE, above the loop: the call is idempotent and its answer cannot
    # change inside it, so a per-entry copy re-walked and re-`lstat`ed every component below
    # the run dir once per claim sidecar.
    guarded_mkdir(dst, base=run_dir)
    for entry in sorted(src.iterdir()):
        if _lead_of(entry.name) not in leads:
            continue
        if artifact_dir(entry):
            guarded_mkdir(dst / entry.name, base=run_dir)
            for payload in sorted(entry.iterdir()):
                _copy_artifact(payload, dst / entry.name / payload.name)
        else:
            _copy_artifact(entry, dst / entry.name)


def _copy_artifact(src: Path, dst: Path) -> None:
    """Copy one artifact file into the sibling, refusing anything that is not one.

    ONE SPELLING of guard-then-copy. Written twice, the two copies carried different refusal
    text and the drift was not cosmetic: the nested one blamed "a link planted at a payload's
    own name" for whatever it found, so an ordinary `mkdir` under a lead's payload directory —
    the run dir is the box's rw bind, so the model can make one — was reported as a planted
    symlink and the source became unbranchable with the cause named backwards. The refusal
    stays LOUD, which is this function's whole posture; what it says is now what it found.

    BYTES, not decoded text. `read_text_utf8` is a strict `read_text(encoding="utf-8")`, so one
    payload carrying an invalid byte raised `UnicodeDecodeError` mid-copy — not a `BranchError`,
    so it reached `open_main_session`'s catch-all AFTER `store.fork` had already committed, and
    every retry repeated it. `shutil.copytree` copied those bytes without looking, and
    `write_guarded` takes `bytes` for exactly this lane (the drain's corpus restore), so the
    guard is kept and the fidelity comes back.
    """
    if not artifact_file(src):
        raise BranchError(f"{src} is {_not_a_plain_file(src)}")
    write_guarded(dst, src.read_bytes())


def _not_a_plain_file(path: Path) -> str:
    """Why `path` is not an artifact a sibling may inherit, in the words of what it actually is."""
    if path.is_symlink():
        return (
            "a symlink — a link planted at an artifact's own name would copy bytes from "
            "outside the run into the sibling under that name")
    if artifact_dir(path):
        return (
            "a directory where a run writes only files (`gather_raw/{lead}/{seq}.json`, "
            "`{lead}.lead.json`, `{lead}.md`) — a sibling's evidence is what the source "
            "actually wrote, and nothing this system writes puts a directory here")
    return (
        "neither a plain file nor a plain directory — a sibling's evidence must be what the "
        "source actually wrote, not what a link or a device node points at")


def _lead_of(name: str) -> str:
    """The lead a per-lead entry belongs to.

    Three spellings across two directories — `l-001/` (a payload subtree), `l-001.lead.json` (a
    claim sidecar) and `l-001.md` (a gather summary) — and all three are the lead id up to the
    first dot. Suffix-stripping rather than a regex per shape, because a shape this function did
    not know would otherwise silently belong to no lead and be dropped from every sibling.
    """
    return name.split(".", 1)[0]


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
