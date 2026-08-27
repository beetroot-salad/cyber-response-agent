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
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart

from defender._io import read_jsonl_rows, read_text_soft, write_guarded
from defender._run_paths import RunPaths
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
    args = getattr(part, "args", None)
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return ""
    return args.get("text", "") if isinstance(args, dict) else ""


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
    try:
        recorded = session_store.resolve_session_id(Path(spec.source_run_dir))
    except (OSError, ValueError):
        # A run dir with no readable pointer is one `open_source_store` has already refused on
        # the path that opens a store; reached any other way, the root is the honest fallback
        # and the refusals below still name what they find.
        recorded = None
    return recorded if recorded is not None else main_session(store)


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


#: What a sibling inherits from the source RUN DIR, beside the document.
#:
#: The message prefix is full of absolute paths into the run dir that produced it — a gather
#: return names `gather_raw/{lead_id}/{seq}.json`, a lead claim names `{lead_id}.lead.json` —
#: and `permission.decide_read` roots the sibling at its OWN run dir, so every one of them is
#: denied to a model reading back its own history. The queries table rides along for the same
#: reason in reverse: `validate` refuses a branch whose source captured nothing, so the
#: sibling's evidence IS those rows, and a run dir that dropped them would report a run that
#: gathered nothing and then reasoned about it.
_INHERITED = ("executed_queries.jsonl", "gather_raw", "gather_summaries")


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
    # A SYMLINK IS CONTENT, whatever it points at. `_inherit_evidence` writes the directory
    # arm through `shutil.copytree`, which resolves its destination — so a link planted at
    # `gather_summaries` puts the source run's payloads outside the sibling's run tree
    # entirely, past the `write_guarded` lane the file arm beside it uses for exactly that
    # reason. An empty linked directory is otherwise indistinguishable from the empty real one
    # a fresh sibling is supposed to have, and the scaffolding plants no links.
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
    from defender.skills.invlang.parser import scan_fences

    target = RunPaths(Path(run_dir)).investigation
    refuse_seeded_run_dir(run_dir)
    source_text, _ = read_text_soft(RunPaths(Path(spec.source_run_dir)).investigation)
    text = source_text if source_text is not None else ""
    fences = fence_count_at(store, source_session(store, spec), spec.branch_message_id, text)
    bounds = scan_fences(text).spans
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
    write_guarded(target, text[: bounds[fences - 1][1]] if fences else "")
    _inherit_evidence(Path(spec.source_run_dir), Path(run_dir))
    return fences


def _inherit_evidence(source_run_dir: Path, run_dir: Path) -> None:
    """Copy the run-dir artifacts the inherited prefix REFERS TO into the sibling's run dir.

    COPIED, not shared or symlinked. The sibling appends to `executed_queries.jsonl` and writes
    new payload sidecars beside the old ones, and a link would put those writes into the source
    run's own record — corrupting the base of the very comparison the branch exists to produce.

    Absent is not an error. A source run that dispatched no gather has no `gather_raw/`, and
    `validate` has already refused the one absence that matters (an empty queries table), so
    everything else here is a directory that legitimately never existed.
    """
    for name in _INHERITED:
        src = source_run_dir / name
        if not src.exists():
            continue
        dst = run_dir / name
        if src.is_dir():
            # `dirs_exist_ok`, because the scaffolding has already made `gather_raw/` — the
            # check above proved it is EMPTY, so this fills a directory rather than merging
            # into another run's.
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            write_guarded(dst, src.read_text(encoding="utf-8"))


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
