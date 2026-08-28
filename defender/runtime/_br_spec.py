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

What a branch request IS, and opening the store it reads from.

Split out of `branch.py` at 1197 lines; imports none of its siblings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any



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
