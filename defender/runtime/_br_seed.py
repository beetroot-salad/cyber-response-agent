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

Writing the sibling: the inherited prefix, the evidence, the lead directories.

The write half of the branch, split out of `branch.py` at 1197 lines. A valid source does
not guarantee a valid prefix, which is why the seeding path meets the artifact schema like
every other writer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


from defender._io import (
    guarded_mkdir,
    read_jsonl_rows,
    read_text_soft,
    write_guarded,
)
from defender._run_paths import RunPaths, artifact_dir, artifact_file

from ._br_spec import BranchError, BranchSpec
from ._br_frontier import _LEAD_DIRS, fence_count_at, leads_at, source_session
from ._br_frontier import _lead_of


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
    from defender._artifact_schema import INVESTIGATION_NAME, validate_artifact
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
    seed = text[: bounds[fences - 1][1]] if fences else ""
    # THE SEED MEETS THE SCHEMA, like every other writer of this artifact (#961/#964's class,
    # third site). This frame reaches `write_guarded` directly — it is host code, not a tool
    # call, so there is no `permission.decide_write` in front of it — and a valid source
    # document does NOT guarantee a valid prefix: the reference rules are order-INDEPENDENT,
    # so a source whose `:R` block cites a lead its `:L findings` block declares one fence
    # LATER is well-formed whole and `undeclared lead` when cut between the two. Measured, not
    # reasoned: no document in the checked-in corpus has that shape, and one built to have it
    # reproduces the refusal exactly.
    #
    # RAISES rather than seeding anyway, unlike `lead_zero`'s best-effort seed. The difference
    # is who is left holding it: that one runs before MAIN's first turn and its failure leaves
    # a model that can still declare the lead itself, while this one hands a SIBLING RUN its
    # entire starting document. Seeding a malformed one gives that run an investigation whose
    # every subsequent append is refused for a fault it did not write and cannot repair —
    # append-only puts the bad bytes out of its reach. This is also the same answer the fence
    # mismatch above already gives, for the same reason: a seed cut wrong is not a seed.
    # THE SEED IS ITS OWN BASELINE, for the reason `committed_investigation_reason` spells
    # out: every check keyed on `current` asks what THIS WRITE INTRODUCES, and an inherited
    # prefix introduces nothing its source had not already committed. With `None`, an unfenced
    # block header the SOURCE committed — legal there, since the write gate scopes that family
    # to what a write adds — reads as newly introduced, and a run whose document ever carried
    # one could never be branched or resumed again. What this call is actually for survives the
    # change untouched: the reference and structure rules are document-global and do not look
    # at the baseline at all, which is why the `undeclared lead` prefix that motivated the
    # check is still refused.
    reason = validate_artifact(INVESTIGATION_NAME, seed, seed)
    if reason is not None:
        raise BranchError(
            f"the {fences}-fence prefix of "
            f"{RunPaths(Path(spec.source_run_dir)).investigation} does not pass validation, so "
            f"the sibling cannot be seeded from it — the source document is well-formed only "
            f"as a whole, and a run started on the prefix could never repair it "
            f"(append-only). {reason}"
        )
    # `write_guarded`, not `write_text`: this writes into the shared run tree, and the seam
    # stages under an unpredictable name and `os.replace`s into place rather than opening the
    # target — so a planted symlink at the sibling's `investigation.md` is replaced instead of
    # followed. The same lane `_tool_append_block` writes this file through.
    write_guarded(target, seed)
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

