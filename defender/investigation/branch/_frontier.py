"""Reading the source run of a turn-N branch: where the fences end, which leads existed, what
the clock said.

Every function here answers a question about the run being branched from without writing
anything.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from collections.abc import Callable, Iterator
from typing import Any

from pydantic_ai.messages import ModelRequest, RetryPromptPart, ToolCallPart, ToolReturnPart

from defender import _clock
from defender.records import Run, RUN_LAYOUT, RunPaths, artifact_dir

from defender.records import session_store
from ._spec import BranchError, BranchSpec


def fence_count_at(
    store: Any, session_id: str, branch_message_id: int, document: str,
) -> int:
    """How many invlang fences the document held at `branch_message_id`.

    Counted in fences, not `append_block` calls: one call can carry several fences,
    one turn several calls, and lead-0's block is written by the host before the model's
    first turn.

    Fences no append accounts for (`total - overall`) were on disk before the model wrote and
    count at every branch point; appended fences count when their tool return (the half the
    prefix carries) is at or before the branch point, joined to the call's text by
    `tool_call_id`. The initial contribution is clamped at zero when the recorded
    appends exceed the current document.
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
                # A refusal (`ModelRetry`) lands nothing; drop it so a reused `tool_call_id`
                # cannot pop the refused text.
                pending.pop(part.tool_call_id, None)
            elif isinstance(part, ToolReturnPart):
                landed = len(scan_fences(pending.pop(part.tool_call_id, "")).bodies)
                overall += landed
                through += landed if row_id <= branch_message_id else 0
    return max(0, len(scan_fences(document).bodies) - overall) + through


def _appended_text(part: Any) -> str:
    """The `text` an `append_block` call carries, however the framework spelled its args."""
    return _call_args(part).get("text", "")


def _call_args(part: Any) -> dict:
    """A `ToolCallPart`'s arguments as a dict: a dict as-is, a JSON string decoded, anything
    else as `{}` (unattributable either way).

    For fence counting only. Lead ids go through `session_store._lead_id_from_args`, whose
    duplicate-key rule this bare `loads` does not share.
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

    `main_session_id`'s `ValueError` (zero or several roots — the wrong store) is re-raised as
    `BranchError` so the driver's store-setup handler catches it.
    """
    try:
        return session_store.main_session_id(store)
    except ValueError as e:
        raise BranchError(f"the source store holds no single root 'main' session: {e}") from e


def source_session(store: Any, spec: BranchSpec, *, source_run: Run) -> str:
    """The source run's own main session — the lineage root only when the source is not itself
    a sibling.

    Using the root for a sibling source would validate and fork against the grandparent's
    transcript while seeding from the source's document. The case pointer records the run's own
    session; when it names none (fresh runs), the root is correct.
    """
    return session_for_run(store, Path(spec.source_run_dir), source_run=source_run)


def session_for_run(store: Any, run_dir: Path, *, source_run: Run) -> str:
    """`source_session`'s answer for a run dir; T0 is derived before a `BranchSpec` exists."""
    try:
        recorded = session_store.resolve_session_id(source_run)
    except (OSError, ValueError):
        # `open_source_store` already refuses an unreadable pointer on the store-opening path;
        # elsewhere the root is the fallback. A run recorded before #1235
        # (`session_store.LegacyRunLink`) is not caught: it is refused, never read as the root.
        recorded = None
    return recorded if recorded is not None else main_session(store)


def branch_point_time(store: Any, run_dir: Path, branch_message_id: int, *, source_run: Run) -> datetime:
    """The moment the branch point was written — the clock a sibling resumes into.

    The run clock's reading in the branch point's fork snapshot (rev 5 C4), whole seconds so it
    round-trips through the `Z`-seconds format `validate` compares against. Not the framework's
    message timestamps, which are wall times a natural run's clock need not agree with; those
    are used only for a source with no snapshot, which `validate` refuses.
    """
    session = session_for_run(store, run_dir, source_run=source_run)
    path = session_store.path_row_ids(store, session)
    if branch_message_id not in path:
        raise BranchError(
            f"message {branch_message_id} is not on {run_dir}'s own main session, so it has no "
            "branch-point time — the id has to be one this run's main path actually holds")
    prefix = session_store.hydrate(store, session, role="analysis")
    upto = prefix[: path.index(branch_message_id) + 1]
    from . import _snapshot  # _snapshot reads this module's frontier
    snapshot = _snapshot.load(store, session, _snapshot.request_count(upto))
    if snapshot is None:
        # No snapshot: `validate` refuses this source (N4), whatever moment is named here.
        return _as_of_of(upto, run_dir, branch_message_id)
    return snapshot.fork_time


def _as_of_of(prefix: list, run_dir: Path, branch_message_id: int) -> datetime:
    """T0 from an already-hydrated prefix slice; shared by `branch_point_time` and `validate`.

    Part timestamps count too: a `ModelRequest` that was never sent has no timestamp, but its
    `ToolReturnPart` does, and falling back to the preceding response would put T0 before the
    evidence landed. Stamps are normalised before `max`, since mixing naive and aware raises
    `TypeError`, which would escape the driver's setup handler.
    """
    stamps = [
        _utc(at) for at in _prefix_stamps(prefix) if isinstance(at, datetime)
    ]
    if not stamps:
        # Never fall back to the wall clock: "now" posing as a branch point is what `as_of`
        # exists to prevent.
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
    """`at` as an aware UTC moment, reading a naive value as UTC.

    Delegates to `_clock.as_utc`, the same rule formatting uses, since `_refuse_bad_as_of`
    compares the two exactly.
    """
    return _clock.as_utc(at)


def _refuse_bad_as_of(spec: BranchSpec, derived: datetime) -> None:
    """Refuse a spec whose clock is not this branch point's.

    A naive or non-UTC `as_of` formats a `Z` that lies by its offset; one that disagrees with
    `branch_point_time` carries another branch point's clock (a copy-paste), undetectable later.
    """
    at = spec.as_of
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


#: The tool whose call/return pair is the only join from a message id to a run's evidence — the
#: name pydantic-ai registers for `tools_gather`'s `gather`. If wrong, no part matches and every
#: sibling silently inherits every lead.
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


def leads_at(store: Any, session_id: str, branch_message_id: int, run_dir: Path, *, source_run: Run) -> set[str]:
    """Which gather leads the run held by `branch_message_id`."""
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
                # The store's own extractor (first-wins on duplicate JSON keys), so this and the
                # `gather_boundary` view never name different leads for one hostile call.
                lead_id = session_store._lead_id_from_args(getattr(part, "args", None))
                if lead_id:
                    pending[part.tool_call_id] = lead_id
                    # Counted on the call, not the return: the question is "could this call have
                    # produced work?", so an unanswered dispatch is not mistaken for lead-0's.
                    dispatches[lead_id] += 1
            elif isinstance(part, RetryPromptPart):
                # Remove only this refused call's contribution; another dispatch may name the
                # same lead.
                _drop_refused_dispatch(pending, dispatches, part.tool_call_id)
            elif isinstance(part, ToolReturnPart):
                claimed = pending.pop(part.tool_call_id, None)
                if claimed is not None and row_id <= branch_message_id:
                    landed.add(claimed)
    return landed | (_known_leads(run_dir, source_run=source_run) - set(dispatches))


def _known_leads(run_dir: Path, *, source_run: Run) -> set[str]:
    """Every lead this run dir names, by any of the three artifacts that name one.

    Not just the query table: a lead is claimed (`gather_raw/{lead}.lead.json`) before it runs
    and may have no rows. Missing its claim, the sibling would re-dispatch an id its prefix
    already used and `claim_lead` would refuse the reuse.
    """
    known = {
        str(row.get("lead_id")) for row in source_run.tables.queries.read_rows()[0]
        if row.get("lead_id")
    }
    paths = RunPaths(source_run.run_dir)
    for directory in (paths.gather_raw, paths.gather_summaries):
        # `artifact_dir`, not `is_dir()`: a planted link would contribute its target's entries.
        if artifact_dir(directory):
            known |= {_lead_of(entry.name) for entry in directory.iterdir()}
    return {lead for lead in known if lead}


def _lead_of(name: str) -> str:
    """The lead a per-lead entry belongs to: the name up to the first dot (`l-001/`,
    `l-001.lead.json`, `l-001.md`). Suffix-stripping, so an unknown shape is not dropped."""
    return name.split(".", 1)[0]


def carried_retries(prefix: list) -> dict[str, int]:
    """The retry count each tool carries into the step after `prefix` — the framework's own
    bookkeeping, replayed over the conversation (rev 5 C1)."""
    retries: dict[str, int] = {}
    for message in prefix:
        if not isinstance(message, ModelRequest):
            continue
        failed = {p.tool_name for p in message.parts
                  if isinstance(p, RetryPromptPart) and p.tool_name}
        succeeded = {p.tool_name for p in message.parts if isinstance(p, ToolReturnPart)}
        if not failed and not succeeded:
            continue
        carried = {tool: n for tool, n in retries.items() if tool not in succeeded}
        carried.update({tool: retries.get(tool, 0) + 1 for tool in failed})
        retries = carried
    return {tool: n for tool, n in retries.items() if n}


def lead_records(run: Run) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """The per-lead write-once records `run`'s folder holds, as `(kind, args)` — each lead's
    claim (`("lead_claim", (lead,))`), raw payloads (`("payload", (lead, seq))`) and gather
    summary (`("gather_summary", (lead,))`) — recognised by the exact name the layout gives
    them: an entry the layout would not name (a stray file, a planted link's odd name) is not
    a record and is left out. Directories are judged without following a link."""
    paths = RunPaths(run.run_dir)
    if artifact_dir(paths.gather_raw):
        for entry in sorted(paths.gather_raw.iterdir()):
            lead = _lead_of(entry.name)
            if artifact_dir(entry):
                for payload in sorted(entry.iterdir()):
                    seq = _lead_of(payload.name)
                    if seq.isascii() and seq.isdecimal() and _named(
                            lambda: RUN_LAYOUT.payload(entry.name, int(seq)).name, payload.name):  # noqa: B023 — called at once
                        yield "payload", (entry.name, int(seq))
            elif _named(lambda: RUN_LAYOUT.lead_claim(lead).name, entry.name):  # noqa: B023 — called at once
                yield "lead_claim", (lead,)
    if artifact_dir(paths.gather_summaries):
        for entry in sorted(paths.gather_summaries.iterdir()):
            lead = _lead_of(entry.name)
            if _named(lambda: RUN_LAYOUT.gather_summary(lead).name, entry.name):  # noqa: B023 — called at once
                yield "gather_summary", (lead,)


def _named(layout_name: Callable[[], str], actual: str) -> bool:
    """Whether `actual` is exactly the layout's name for a record (`False` when the layout
    refuses the record's components)."""
    try:
        return layout_name() == actual
    except ValueError:
        return False
