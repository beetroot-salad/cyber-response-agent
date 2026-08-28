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

Reading the source run: where the fences end, which leads existed, what the clock said.

Every function here is a QUESTION about the run being branched from, and answers it
without writing anything. Split out of `branch.py` at 1197 lines.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart

from defender import _clock
from defender._io import (
    read_jsonl_rows,
    read_text_soft,
)
from defender._run_paths import RunPaths, artifact_dir

from . import session_store
from ._br_spec import BranchError, BranchSpec


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
    from defender.skills.invlang.parser import scan_fences

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
                landed = len(scan_fences(pending.pop(part.tool_call_id, "")).bodies)
                overall += landed
                through += landed if row_id <= branch_message_id else 0
    return max(0, len(scan_fences(document).bodies) - overall) + through


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


def _lead_of(name: str) -> str:
    """The lead a per-lead entry belongs to.

    Three spellings across two directories — `l-001/` (a payload subtree), `l-001.lead.json` (a
    claim sidecar) and `l-001.md` (a gather summary) — and all three are the lead id up to the
    first dot. Suffix-stripping rather than a regex per shape, because a shape this function did
    not know would otherwise silently belong to no lead and be dropped from every sibling.
    """
    return name.split(".", 1)[0]
