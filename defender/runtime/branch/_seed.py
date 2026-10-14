"""Writing a turn-N branch sibling: the inherited document prefix, the evidence, the lead
directories.

A valid source does not guarantee a valid prefix, so the seed meets the artifact schema like
every other writer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


from defender import _alert_input
from defender._io import (
    load_json_artifact,
)
from defender.run_repository import RecordHandle, Run, RUN_LAYOUT, RunPaths, artifact_dir

from ..run_state import RunState
from ._spec import BranchError, BranchSpec
from ._frontier import _lead_dirs, fence_count_at, leads_at, source_session


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


def seed_investigation(store: Any, spec: BranchSpec | None, run_state: RunState, *, run: Run, source_run: Run | None = None) -> int:
    """Write the sibling's `investigation.md`: the source's document as it stood at the branch,
    then its evidence (`_inherit_evidence`, which records the inherited queries rows into the
    sibling's `run_state`).

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

    run_dir = run_state.run_dir
    refuse_seeded_run_dir(run_dir)
    # `read_guarded`, not `read_text_soft`: the source run dir was a box's rw bind, so the
    # document may be a planted link. Unreadable seeds empty, like missing.
    if source_run is None:
        raise BranchError("a resumed run requires its source Run")
    source_text = source_run.documents.investigation.read()
    text = source_text if source_text is not None else ""
    fences = fence_count_at(store, source_session(store, spec, source_run=source_run), spec.branch_message_id, text)
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
    # The record retains pristine-sibling refusal and validates the inherited baseline.
    run.documents.investigation.seed(seed)
    _inherit_evidence(
        source_run, run_state,
        leads_at(store, source_session(store, spec, source_run=source_run), spec.branch_message_id,
                 Path(spec.source_run_dir), source_run=source_run), run=run)
    return fences


def source_alert(source_run: Run) -> dict[str, Any] | None:
    """The source run's alert (the case input) as a JSON object, or `None` when it is absent,
    not a plain file, or not a JSON object `load_json_artifact` accepts (nested too deep
    included). The one reader of it for the question-writer and the branching oracle's real
    data (#1224): never raises."""
    try:
        # Read only as the run's record vouches for it: a replaced alert is no alert here.
        raw, _record = _alert_input.verify_input_bytes(
            source_run.facts.alert.read_bytes().data, source_run.facts.alert_record.read(),  # lint-whole-read: ok — RecordHandle reads bounded original bytes through the rooted core
            run_name=str(source_run.id))
        doc, unreadable = load_json_artifact(raw.decode("utf-8"))
    except (OSError, ValueError, BranchError, _alert_input.AlertReplaced):
        return None
    return doc if unreadable is None and isinstance(doc, dict) else None


def _inherit_evidence(source_run: Run, run_state: RunState, leads: set[str], *, run: Run) -> None:
    """Copy only the canonical evidence selected at the branch point, through both Runs."""
    source_run_dir = source_run.run_dir
    sibling = RunPaths(run.run_dir)
    source = RunPaths(source_run_dir)
    if not sibling.alert.exists():
        alert = source_run.facts.alert.read_bytes()  # lint-whole-read: ok — RecordHandle delegates to the bounded no-follow core
        if not alert.absent:
            try:
                raw, record_text = _alert_input.verify_input_bytes(
                    alert.data, source_run.facts.alert_record.read(), run_name=source_run_dir.name)
            except _alert_input.AlertReplaced as replaced:
                raise BranchError(str(replaced)) from replaced
            run.facts.alert.write(raw)
            run.facts.alert_record.replace(record_text)
    rows, _malformed, result = source_run.tables.queries.read_rows()
    if result.reason is not None:
        raise BranchError(f"{source.executed_queries} could not be copied: {result.reason}")
    if not result.absent:
        selected = [row for row in rows if str(row.get("lead_id", "")) in leads]
        run.tables.queries.create("".join(json.dumps(row) + "\n" for row in selected))
        run_state.inherit_rows(selected)
    for src, dst in ((source.gather_raw, sibling.gather_raw),
                     (source.gather_summaries, sibling.gather_summaries)):
        _inherit_lead_dir(src, dst, leads, run.run_dir, source_run=source_run, run=run)


def _inherit_lead_dir(src: Path, dst: Path, leads: set[str], run_dir: Path,
                      *, source_run: Run, run: Run) -> None:
    """Enumerate canonical names before reading or descending into inherited evidence."""
    if not src.exists():
        return
    if not artifact_dir(src):
        raise BranchError(f"{src} is not a plain directory")
    raw = src.name == RUN_LAYOUT.gather_raw.name
    if not raw:
        # Only the holding folder is prepared; this component creates no summary record.
        run.documents.gather_summaries(src.name).ensure_parent()
    names = _lead_record_names(leads, raw=raw)
    valid_leads = set(names.values())
    for entry in sorted(src.iterdir()):
        if raw and entry.name in valid_leads:
            _inherit_payload_dir(entry, source_run=source_run, run=run)
            continue
        lead = names.get(entry.name)
        if lead is None:
            continue
        source_record = (source_run.tables.leads(lead) if raw
                         else source_run.documents.gather_summaries(lead))
        target_record = (run.tables.leads(lead) if raw
                         else run.documents.gather_summaries(lead))
        _copy_artifact(source_record, target_record)


def _lead_record_names(leads: set[str], *, raw: bool) -> dict[str, str]:
    """Canonical selected file names, as the layout owner can produce them."""
    names = {}
    for lead in leads:
        try:
            name = (RUN_LAYOUT.lead_claim(lead).name if raw
                    else RUN_LAYOUT.gather_summary(lead).name)
        except ValueError:
            continue
        names[name] = lead
    return names


def _inherit_payload_dir(entry: Path, *, source_run: Run, run: Run) -> None:
    if not artifact_dir(entry):
        raise BranchError(f"{entry} is not a plain directory")
    run.tables.payloads(entry.name, 0).ensure_parent()
    for payload in sorted(entry.iterdir()):
        stem = payload.stem
        if not stem.isascii() or not stem.isdecimal():
            continue
        seq = int(stem)
        if payload.name != RUN_LAYOUT.payload(entry.name, seq).name:
            continue
        _copy_artifact(source_run.tables.payloads(entry.name, seq),
                       run.tables.payloads(entry.name, seq))


def _copy_artifact(src: RecordHandle, dst: RecordHandle) -> None:
    """Copy recognized bytes intact, refusing a missing or unreadable recognized artifact."""
    data = _plain_bytes(src)
    try:
        dst.write(data)
    except OSError as error:
        raise BranchError(f"the source record could not be copied into the sibling: {error}") from error


def _plain_bytes(record: RecordHandle) -> bytes:
    found = record.read_bytes()  # lint-whole-read: ok — a RecordHandle, whose core enforces READ_LIMIT
    if found.data is None:
        raise BranchError(f"the source record could not be copied into the sibling: {found.reason}")
    return found.data


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

