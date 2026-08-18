from __future__ import annotations

import json
import tarfile
from pathlib import Path

from defender._clock import now_iso
from defender._env import env_int
from defender.learning.core.config import _log
from defender.runtime.scrub import RunTainted, verdict_path


# How many tainted trees may accumulate before the lane stops preserving them. A CAP, never
# a TTL: past it we refuse to write and say so, and nothing already written is evicted — a
# timer that deleted the only forensic record of a suspected in-box RCE would be the very bug
# this module exists to fix, just on a schedule.
_MAX_ENV = "LEARNING_TAINT_QUARANTINE_MAX"
_MAX_DEFAULT = 10


def _archive_tree(wt: Path, dest: Path) -> None:
    """Write `wt` to `dest` as a gzipped tar.

    `tarfile` at its default `dereference=False` is what makes the artifact INERT, and is the
    whole reason this is an archive rather than a `mv`: a symlink is stored as METADATA — type
    flag plus target string — and never followed. Nothing that later walks the host (a
    `grep -r`, an editor indexer, a backup job) can deref a link that exists only as a tar
    member, so unpacking becomes a deliberate operator act. Relocating the worktree would
    preserve a live, dereferenceable link on the host permanently.
    """
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(wt, arcname=wt.name)


def _tree_verdict(wt: Path) -> dict:
    """The verdict lives OUTSIDE the tree, so an archive (or any move/copy) carries nothing
    about it unless the mover reads it explicitly and writes it down separately. `{}` — never
    an absent key — for a tree with no verdict, so a skipped scan cannot read as a clean one
    to a human triaging the quarantine directory."""
    p = verdict_path(wt)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _manifest(
    wt: Path, archive: Path, *, batch_id: str, branch: str, label: str, taint: RunTainted,
) -> dict:
    # `__context__` is the work's own failure, which the taint outranked on its way out: the
    # reason the batch was dying BEFORE the tree was found tainted. Recorded rather than left
    # to implicit chaining, since the traceback is gone once the tree is.
    cause = taint.__context__
    return {
        "batch_id": batch_id,
        "branch": branch,
        "label": label,
        "worktree": str(wt),
        "archive": archive.name,
        "quarantined_at": now_iso(),
        "taint": str(taint),
        "cause": repr(cause) if cause is not None else None,
        "verdict": _tree_verdict(wt),
        "findings": [
            {
                "path": str(f.path), "kind": f.kind, "filemode": f.filemode,
                "nlink": f.nlink, "target": f.target, "detail": f.detail,
            }
            for f in taint.findings
        ],
    }


def preserve_tainted_tree(
    wt: Path,
    quarantine_dir: Path,
    *,
    batch_id: str,
    branch: str,
    label: str,
    taint: RunTainted,
) -> Path | None:
    """Archive a tainted worktree before its caller destroys it. Returns the archive path,
    or None if nothing was preserved.

    Never raises. A failure to quarantine must not replace the taint that brought us here —
    the taint is the more important signal, and a preserve step that masked it would trade
    one lost report for another. Every outcome is logged, because a silent failure here is
    indistinguishable from a tree that was never tainted.
    """
    archived: Path | None = None
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        held = sum(1 for _ in quarantine_dir.glob("*.tar.gz"))
        cap = env_int(_MAX_ENV, _MAX_DEFAULT)
        if held >= cap:
            _log(
                f"{label}: {held} quarantined tree(s) already held at "
                f"{quarantine_dir} (cap {cap}, {_MAX_ENV}) — NOT preserving {wt}. The "
                f"existing artifacts are untouched; clear them by hand once triaged."
            )
            return None
        archive = quarantine_dir / f"{batch_id}.tar.gz"
        try:
            _archive_tree(wt, archive)
        except BaseException:
            # A half-written tarball is not evidence, and leaving one behind spends the cap on
            # failures until it refuses every real archive.
            archive.unlink(missing_ok=True)
            raise
        archived = archive
        manifest = quarantine_dir / f"{batch_id}.json"
        manifest.write_text(
            json.dumps(
                _manifest(wt, archive, batch_id=batch_id, branch=branch, label=label,
                          taint=taint),
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        _log(
            f"{label}: tainted worktree preserved at {archive} "
            f"({len(taint.findings)} finding(s), manifest {manifest.name})"
        )
        return archive
    except Exception as e:  # noqa: BLE001 — the taint outranks any failure to preserve it
        # What survived decides what the operator is told: saying "the evidence is being lost"
        # over a tarball that is sitting right there would send triage the wrong way.
        residue = (
            f"the archive at {archived} survives, but WITHOUT its manifest"
            if archived is not None
            else "the tree is about to be destroyed and this taint's evidence is being lost"
        )
        _log(f"{label}: FAILED to quarantine the tainted worktree {wt}: {e!r} — {residue}")
        return None
