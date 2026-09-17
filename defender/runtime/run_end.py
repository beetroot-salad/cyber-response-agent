"""The run-end record: how a run ended, on a path no box ever gets an rw bind on (#1047).

**Why a sidecar and not a file inside the run dir.** The design's first draft put the exit
class in the forced `report.md`'s frontmatter; the cold review refuted it — `validate_report`
admits an unknown key, and the judge reads the archived COPY of a file the box had an rw bind
on, so a planted `truncated_by:` line would have let the graded subject exclude its own world
from grading. This module exists to keep the value off that path entirely: the sidecar lives
BESIDE the run dir, at a path derived from the run dir's own name — `scrub.verdict_path`'s
shape, the precedent fork F2 reading A chose.

The record carries TWO fields. `truncated_by` is the exit class (a `TRUNCATED_BY_VALUES`
member, or `None` for a run that ended cleanly — `None` is valid CONTENT, not "absent"), and
`closed_before_cut` says whether the model had already closed
(`challenge_gate.ReviewState.of(deps).closed`) at the moment the exit was stamped — without it
a genuine model verdict is indistinguishable from one the host manufactured.

The one production writer is the driver (`runtime/driver/__init__.py`, before the forced
report write); the one production reader is the archive (`learning/branch/archive.py`), which
copies this file's content into `worlds/<label>/run_end.json` — never anything inside the run
dir itself.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defender._io import read_guarded, write_guarded
from defender.runtime.session_store import normalized_truncated_by


def sidecar_path(run_dir: Path) -> Path:
    """The host-side run-end record's path — beside `run_dir`, never inside it.

    A pure function of a path the host already holds, exactly like `scrub.verdict_path`: O3's
    whole security argument is that no box-writable content is an input to this path.
    """
    run_dir = Path(run_dir)
    return run_dir.parent / f"{run_dir.name}.run-end.json"


def record_doc(truncated_by: str | None, closed_before_cut: bool) -> dict[str, Any]:
    """The record's document — both fields, spelled once for the writer and the fixtures."""
    return {"truncated_by": truncated_by, "closed_before_cut": bool(closed_before_cut)}


def write_sidecar(run_dir: Path, *, truncated_by: str | None, closed_before_cut: bool) -> None:
    """Write the host-side sidecar beside `run_dir`. UNCONDITIONAL for every run that reaches
    the agent loop — a clean run writes `{"truncated_by": null, "closed_before_cut": false}`,
    not nothing, so "not cut short" and "the host never got to say" stay two different states.

    Through `write_guarded`'s `replace` mode, the same seam every other shared-tree write in
    this codebase uses — a stale sidecar from a retried run is atomically replaced, never
    appended to or read-modified.
    """
    write_guarded(sidecar_path(run_dir), json.dumps(record_doc(truncated_by, closed_before_cut)))


def read_sidecar(run_dir: Path) -> dict[str, Any] | None:
    """The host-side sidecar's document, or `None` when it cannot be read as one.

    `None` covers: nothing at the path, a symlink or hard link there (refused by
    `read_guarded`'s own screen), a directory squatting the name, undecodable bytes, truncated
    JSON, and a JSON value that is not an object (a list, a bare string). Every one of these
    folds into the archive's existing "the sidecar could not be read" arm — skipped and
    reported, never a fourth answer invented for this one artifact.

    `truncated_by` is re-normalized through `normalized_truncated_by` even though the driver is
    the record's only legitimate producer: defense in depth against a corrupted or
    hand-edited host file, not a security boundary — the box never reaches this path at all.
    """
    text, _refusal = read_guarded(sidecar_path(run_dir))
    if text is None:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    return record_doc(
        normalized_truncated_by(doc.get("truncated_by")),
        bool(doc.get("closed_before_cut", False)),
    )


__all__ = ["read_sidecar", "record_doc", "sidecar_path", "write_sidecar"]
