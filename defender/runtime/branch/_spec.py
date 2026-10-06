"""What a turn-N branch request is, and opening the store it reads from.

Imports none of its siblings.
"""

from __future__ import annotations

import dataclasses
import json
from defender._model import model, unwrap_before
from datetime import datetime
from pathlib import Path
from typing import Any, get_type_hints

from pydantic import model_validator



from defender._run_paths import RUN_LAYOUT, RunPaths

from .. import session_store


class BranchError(Exception):
    """A branch point that cannot carry a sibling world."""


@model(frozen=True)
class BranchSpec:
    """One resume: which run, which message, and what to say on arrival.

    `continuation_prompt` is a parameter because its wording biases the run (e.g. toward
    closing over gathering); it is part of the measured instrument, owned by the caller.

    `as_of` is the branch point's own moment. Required, not defaulted to "now", which would
    stamp every sibling's payloads with execution time. `validate` refuses a value that
    disagrees with `branch_point_time`.
    """

    source_run_dir: Path
    branch_message_id: int
    continuation_prompt: str
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
    "continuation_prompt":
        "the prompt is part of the measured instrument and has to be the text that was sent",
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


def open_source_store(run_dir: Path) -> Any:
    """The finished run's own store, opened for writing.

    A sibling forks into the source database, where the prefix rows live. `runs_base` is
    derived as the writer did (`run_dir.parent`) and checked against the path the pointer
    recorded: `open_store` creates-if-missing, so a wrong derivation would silently open an
    empty database. Both sides are resolved before comparing, since callers spell paths
    differently (relative, `..`, symlinked `/tmp` on macOS).
    """
    # Resolve first: `Path("run-x").parent` is `.`, which would derive the store under the cwd.
    run_dir = Path(run_dir).resolve()
    # Every malformed-pointer failure (including `store_path_for`'s `InvalidCaseId`) becomes
    # `BranchError`, which the driver's store-setup handler catches.
    try:
        pointer = json.loads(
            RunPaths(run_dir).session_pointer.read_text(encoding="utf-8"))  # lint-whole-read: ok — session pointer: host-written tiny JSON; box-writable in the rw run dir, so bounded by the box fsize limit; per-run reader
        recorded = Path(pointer["store_path"]).resolve()
        case_id = pointer["case_id"]
        derived = session_store.store_path_for(case_id, runs_base=run_dir.parent).resolve()
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BranchError(
            f"{run_dir} carries no readable case pointer "
            f"({RUN_LAYOUT.session_pointer}): {e!r}") from e
    if derived != recorded:
        raise BranchError(
            f"{run_dir} records its store at {recorded}, but its case {case_id!r} under "
            f"runs_base {run_dir.parent} resolves to {derived} — opening the derived path "
            "would create an empty database and lose the branch point")
    return session_store.open_store(case_id=case_id, runs_base=run_dir.parent)


def store_factory_for(spec: BranchSpec):
    """A `driver.StoreFactory` that hands back the source run's store; both arguments are
    ignored because a resume joins the source case rather than minting one."""
    def factory(case_id: str, run_dir: Path) -> Any:  # noqa: ARG001 — the factory's shape
        return open_source_store(spec.source_run_dir)

    return factory
