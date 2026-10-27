"""What a turn-N branch request is, and opening the store it reads from.

Imports none of its siblings.
"""

from __future__ import annotations

import dataclasses
import json
from contextlib import AbstractContextManager
from defender._model import model, unwrap_before
from datetime import datetime
from pathlib import Path
from typing import Any, get_type_hints

from pydantic import model_validator



from defender.records import Run, RunPaths

from defender.records import session_store
from defender.records._seeded import BranchError


@model(frozen=True)
class BranchSpec:
    """One resume: which run, and which of its MAIN responses to fork at.

    It carries nothing to say on arrival (#1255 D1, P4): an arm resumes with no user message,
    so the instrument adds nothing to the model's input that a natural run would not get.

    `as_of` is the branch point's own moment. Required, not defaulted to "now", which would
    stamp every sibling's payloads with execution time. `validate` refuses a value that
    disagrees with `branch_point_time`.
    """

    source_run_dir: Path
    branch_message_id: int
    as_of: datetime

    # Type-check every field before pydantic does and raise `BranchError`, the class callers
    # catch; pydantic's own `ValidationError` would escape their handlers. `bool` is refused as
    # an `int` for the same reason.
    @model_validator(mode="before")
    @classmethod
    def _fields_are_typed(cls, value: Any) -> Any:
        given = unwrap_before(cls, value)
        if not isinstance(given, dict):
            return given
        for name, expected in _FIELD_TYPES.items():
            if name not in given:
                continue  # pydantic names the missing field itself
            got = given[name]
            if not isinstance(got, expected) or (expected is int and isinstance(got, bool)):
                raise BranchError(
                    f"{name} must be {'an' if expected is int else 'a'} {expected.__name__}, "
                    f"got {got!r} — {_WHY[name]}")
        return given


#: What a wrongly-typed value of each field would have meant. Types are read off the class; a
#: new field without an entry here fails at import.
_WHY: dict[str, str] = {
    "source_run_dir": "a spelling of a path is not the path the store is opened from",
    "branch_message_id":
        "a branch point is a message id this run's own store holds, not a spelling of one",
    "as_of": "a branch point without a moment cannot pin the clock its siblings resume into",
}


def _field_types() -> dict[str, type]:
    """`BranchSpec`'s field name -> the runtime class its annotation names, resolved once.

    A union or generic annotation is refused at import rather than mis-checked.
    """
    hints = get_type_hints(BranchSpec)
    out: dict[str, type] = {}
    for f in dataclasses.fields(BranchSpec):
        hint = hints[f.name]
        if not isinstance(hint, type):
            raise TypeError(f"BranchSpec.{f.name} is annotated {hint!r}, which the "
                            "before-validator cannot isinstance-check — add an arm for it")
        if f.name not in _WHY:
            raise KeyError(f"BranchSpec.{f.name} has no entry in _WHY — say what a "
                           "wrongly-typed value would have meant")
        out[f.name] = hint
    return out


_FIELD_TYPES = _field_types()


def open_source_store(run_dir: Path, *, source_run: Run) -> Any:
    """The finished run's own store, for writing: its pointer is checked now, and the store
    opens when the returned context manager's `with` block starts (`session_store.open_store`).

    A sibling forks into the source database, where the prefix rows live. The store's path is
    derived as the writer did (the run folder's own `RunPaths.session_paths()`) and checked
    against the path the pointer recorded: `open_store` creates-if-missing, so a wrong
    derivation would silently open an empty database. Both sides are resolved before
    comparing, since callers spell paths differently (relative, `..`, symlinked `/tmp` on
    macOS).
    """
    # Resolve first: `Path("run-x").parent` is `.`, which would derive the store under the cwd.
    run_dir = source_run.run_dir.resolve()
    sessions = RunPaths(run_dir).session_paths()
    if source_run.observability.session_pointer.read_result().absent:
        _refuse_legacy(run_dir)
    # Every malformed-pointer failure (including `store_path_for`'s `InvalidCaseId`) becomes
    # `BranchError`, which the driver's store-setup handler catches.
    try:
        pointer = json.loads(
            source_run.observability.session_pointer.read())
        recorded = Path(pointer["store_path"]).resolve()
        case_id = pointer["case_id"]
        derived = session_store.store_path_for(case_id, sessions=sessions).resolve()
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BranchError(
            f"{run_dir} carries no readable case pointer "
            f"({RunPaths(run_dir).session_pointer().name}): {e!r}") from e
    if derived != recorded:
        raise BranchError(
            f"{run_dir} records its store at {recorded}, but its case {case_id!r} resolves "
            f"to {derived} beside the run — opening the derived path would create an empty "
            "database and lose the branch point")
    return session_store.open_store(case_id=case_id, sessions=sessions)


def source_store_if_any(run_dir: Path, *, source_run: Run) -> AbstractContextManager[Any] | None:
    """The finished run's own store to open in a `with` (`open_source_store`), or `None` when
    it carries no session pointer.

    Only an absent pointer means "no session". `open_source_store` raises one class for both a
    missing pointer and one that does not reconcile, so the presence check is made here and a
    mismatch still propagates as a refusal rather than silently taking a storeless fallback
    (wrong T0, the finished document's frontier, no fixed prefix). So does a run recorded
    before #1235, whose link is still inside its folder: it is not a run with no session.
    """
    if source_run.observability.session_pointer.read_result().absent:
        _refuse_legacy(Path(run_dir))
        return None
    return open_source_store(run_dir, source_run=source_run)


def _refuse_legacy(run_dir: Path) -> None:
    """A run recorded before #1235 (`session_store.refuse_legacy_link`), refused as this
    module's `BranchError`, the class every caller of a source-store open handles."""
    try:
        session_store.refuse_legacy_link(run_dir)
    except session_store.LegacyRunLink as e:
        raise BranchError(str(e)) from e


def store_factory_for(spec: BranchSpec, *, source_run: Run):
    """A `driver.StoreFactory` that hands back the source run's store to open; both arguments
    are ignored because a resume joins the source case rather than minting one."""
    def factory(case_id: str, run_dir: Path) -> AbstractContextManager[Any]:  # noqa: ARG001 — the factory's shape
        return open_source_store(spec.source_run_dir, source_run=source_run)

    return factory
