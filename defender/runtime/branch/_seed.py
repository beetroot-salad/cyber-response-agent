"""Writing a turn-N branch sibling: the inherited document prefix, the evidence, the lead
directories.

A valid source does not guarantee a valid prefix, so the seed meets the artifact schema like
every other writer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


from defender._io import (
    read_bytes_capped,
    guarded_mkdir,
    read_guarded,
    read_jsonl_rows,
    write_guarded,
)
from defender.run_repository import RUN_LAYOUT, RunPaths, artifact_dir, artifact_file

from ._spec import BranchError, BranchSpec
from ._frontier import _lead_dirs, fence_count_at, leads_at, source_session
from ._frontier import _lead_of


#: Derived from `_lead_dirs()` so the census, the copy and the seeded-dir refusal cannot name
#: different sets.
def _inherited() -> tuple[str, ...]:
    """The run-dir entries a sibling inherits from its source: the queries table plus the two
    per-lead directories."""
    return (RUN_LAYOUT.executed_queries.name, *_lead_dirs())


def refuse_seeded_run_dir(run_dir: Path) -> None:
    """Refuse a sibling run dir that already holds inherited state.

    Separate so it can run before `store.fork`, which commits; a retried resume would otherwise
    leave an orphan session each time.
    """
    run_dir = Path(run_dir)
    present = [name for name in (RunPaths(run_dir).investigation.name, *_inherited())
               if _holds_content(run_dir / name)]
    if present:
        raise BranchError(
            f"{run_dir} already holds {present} — a resumed run inherits those from its "
            "source, and a run dir that already carries them is not a fresh sibling: seeding "
            "over them would interleave two runs' evidence in artifacts that are append-only")


def _holds_content(path: Path) -> bool:
    """Does `path` hold anything a run put there?

    Not mere existence: scaffolding creates empty dirs like `gather_raw/` for every run.
    """
    # A symlink counts as content, refused here before the fork rather than later in the copy
    # (after `store.fork` has committed). The scaffolding plants no links.
    if path.is_symlink():
        return True
    if path.is_dir():
        return any(path.iterdir())
    return path.is_file() and path.stat().st_size > 0


def seed_investigation(store: Any, spec: BranchSpec | None, run_dir: Path) -> int:
    """Write the sibling's `investigation.md`: the source's document as it stood at the branch.

    A fresh run (`spec is None`) seeds nothing and returns 0. A resume gets a fresh run dir, so
    without this the inherited history would point at a document that does not exist there.

    Truncated at the branch point, at the same fence count `frontier_at_branch` uses, so the
    sibling does not inherit the source's later conclusions and the seed matches the frontier
    `validate` accepted. Sliced from the original bytes (keeping prose between blocks) and cut
    at a fence end, so trailing prose — where the `## REPORT` section goes — is excluded.

    Returns the fence count written.
    """
    if spec is None:
        return 0
    from defender._artifact_schema import validate_artifact
    from defender.skills.invlang.parser import scan_fences

    target = RunPaths(Path(run_dir)).investigation
    refuse_seeded_run_dir(run_dir)
    # `read_guarded`, not `read_text_soft`: the source run dir was a box's rw bind, so the
    # document may be a planted link. Unreadable seeds empty, like missing.
    source_text, _ = read_guarded(RunPaths(Path(spec.source_run_dir)).investigation)
    text = source_text if source_text is not None else ""
    fences = fence_count_at(store, source_session(store, spec), spec.branch_message_id, text)
    bounds = scan_fences(text).spans
    if fences > len(bounds):
        # `validate` already refuses a snapped frontier; re-checked because a fork separates
        # the two reads and slicing short would be silent.
        raise BranchError(
            f"{RunPaths(Path(spec.source_run_dir)).investigation} holds {len(bounds)} "
            f"fence(s) but the branch point maps to {fences} — the document and the session "
            "disagree about what had landed, and a seed cut from either is a guess")
    seed = text[: bounds[fences - 1][1]] if fences else ""
    # The seed meets the schema: this host write has no `decide_write` in front of it, and a
    # valid source does not guarantee a valid prefix (reference rules are order-independent, so
    # a lead declared one fence later is `undeclared` in the cut). Raises rather than seeding
    # anyway: append-only would leave the sibling unable to repair bytes it did not write.
    #
    # The seed is its own baseline: checks keyed on the baseline ask what a write introduces,
    # and a prefix introduces nothing its source had not committed (e.g. an unfenced header, or
    # a `:V` whose `:E` lands later). Document-global rules still apply.
    reason = validate_artifact(RUN_LAYOUT.investigation.name, seed, seed)
    if reason is not None:
        raise BranchError(
            f"the {fences}-fence prefix of "
            f"{RunPaths(Path(spec.source_run_dir)).investigation} does not pass validation, so "
            f"the sibling cannot be seeded from it — the source document is well-formed only "
            f"as a whole, and a run started on the prefix could never repair it "
            f"(append-only). {reason}"
        )
    # `write_guarded` replaces a planted symlink at the target instead of following it.
    write_guarded(target, seed)
    _inherit_evidence(
        Path(spec.source_run_dir), Path(run_dir),
        leads_at(store, source_session(store, spec), spec.branch_message_id,
                 Path(spec.source_run_dir)))
    return fences


def _inherit_evidence(source_run_dir: Path, run_dir: Path, leads: set[str]) -> None:
    """Copy the evidence the inherited prefix refers to into the sibling's run dir.

    Copied, not linked: the sibling appends to these and must not write into the source's
    record. Absent directories are fine (`validate` already refused an empty queries table).
    Truncated to `leads` held at the branch point, so later evidence does not leak in.
    """
    # The alert (case input) is copied here so every resume caller gets it, even if a launcher
    # already did. Not in `_inherited()`: a freshly materialised sibling legitimately holds it.
    alert = RunPaths(source_run_dir).alert
    if alert.exists() or alert.is_symlink():
        if not artifact_file(alert):
            raise BranchError(
                f"{alert} is not a plain file — the alert is the case input both siblings "
                f"investigate, and one that is {_not_a_plain_file(alert)} is not the source "
                "run's own")
        # Bytes, matching `materialize_run`'s `shutil.copy`, so the copy is exact even if not
        # valid UTF-8.
        write_guarded(RunPaths(run_dir).alert, read_bytes_capped(alert))

    queries = RunPaths(source_run_dir).executed_queries
    if queries.exists() or queries.is_symlink():
        # Refused, not skipped: skipping would seed a sibling that looks like it gathered nothing.
        if not artifact_file(queries):
            raise BranchError(
                f"{queries} is not a plain file — following a link at the queries table's own "
                "name would seed the sibling's evidence from outside the source run")
        rows = [row for row in read_jsonl_rows(queries) if str(row.get("lead_id", "")) in leads]
        write_guarded(
            RunPaths(run_dir).executed_queries,
            # Whole-file rewrite, outside the append-mode JSONL gate's scope; left unmarked so
            # a future conversion to append would be caught.
            "".join(json.dumps(row) + "\n" for row in rows))
    for name in _lead_dirs():
        _inherit_lead_dir(source_run_dir / name, run_dir / name, leads, run_dir)


def _inherit_lead_dir(src: Path, dst: Path, leads: set[str], run_dir: Path) -> None:
    """Copy the entries of one per-lead directory that belong to `leads`.

    Per entry through the guarded lane, so each is `lstat`-checked and a symlink planted by the
    model (the run dir is a box's rw bind) is refused rather than followed. Refusals raise:
    skipping silently would look like a lead that gathered nothing.
    """
    if not src.exists():
        return
    if not artifact_dir(src):
        raise BranchError(
            f"{src} is not a plain directory — a sibling's evidence is copied out of it, and "
            "following a link here would seed the run from outside the source's own tree")
    # `write_guarded` does not create parents, so make the destination here, once.
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

    Copies bytes, not decoded text, so an invalid UTF-8 payload does not raise mid-copy after
    the fork has committed. The refusal names what was actually found.
    """
    if not artifact_file(src):
        raise BranchError(f"{src} is {_not_a_plain_file(src)}")
    write_guarded(dst, read_bytes_capped(src))


def _not_a_plain_file(path: Path) -> str:
    """Why `path` is not an artifact a sibling may inherit, in the words of what it actually is."""
    if path.is_symlink():
        return (
            "a symlink — a link planted at an artifact's own name would copy bytes from "
            "outside the run into the sibling under that name")
    if artifact_dir(path):
        return (
            "a directory where a run writes only files (`gather_raw/{lead}/{seq}.json`, "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "`{lead}.lead.json`, `{lead}.md`) — a sibling's evidence is what the source "
            "actually wrote, and nothing this system writes puts a directory here")
    return (
        "neither a plain file nor a plain directory — a sibling's evidence must be what the "
        "source actually wrote, not what a link or a device node points at")

