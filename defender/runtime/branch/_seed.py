"""Writing a turn-N branch sibling's folder: restored from the fork snapshot of its branch
point (`_snapshot`), its alert inherited when it has none.

The restored document meets the artifact schema like every other writer
(`run.documents.investigation.seed`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


from defender.records import _alert_input
from defender._io import (
    load_json_artifact,
)
from defender.records import Run, RUN_LAYOUT, RunPaths

from ..run_state import RunState
from . import _snapshot
from ._spec import BranchError
from ._frontier import _lead_dirs


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


def restore_run_folder(snapshot: _snapshot.ForkSnapshot, run_state: RunState, *, run: Run,
                       source_run: Run) -> None:
    """Restore a sibling's folder from its branch point's snapshot (`ForkSnapshot.
    restore_files`), after giving it the source's verified alert when it has none of its own
    (the front door normally placed it at setup, #1222)."""
    _inherit_alert(source_run, run)
    snapshot.restore_files(source_run, run, run_state)


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


def _inherit_alert(source_run: Run, run: Run) -> None:
    """Give a sibling with no alert of its own the source's, verified against its record."""
    if RunPaths(run.run_dir).alert.exists():
        return
    alert = source_run.facts.alert.read_bytes()  # lint-whole-read: ok — RecordHandle delegates to the bounded no-follow core
    if alert.absent:
        return
    try:
        raw, record_text = _alert_input.verify_input_bytes(
            alert.data, source_run.facts.alert_record.read(), run_name=source_run.run_dir.name)
    except _alert_input.AlertReplaced as replaced:
        raise BranchError(str(replaced)) from replaced
    run.facts.alert.write(raw)
    run.facts.alert_record.replace(record_text)
