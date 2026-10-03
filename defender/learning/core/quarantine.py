from __future__ import annotations

import json
import logging
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING

from defender._clock import now_iso
from defender._env import env_int
from defender.runtime.scrub import RunTainted, verdict_path

if TYPE_CHECKING:
    from defender.learning.core.config import DrainLabel

_logger = logging.getLogger(__name__)


# How many tainted trees may accumulate before the lane stops preserving them. A cap, not a
# TTL: past it we refuse to write and say so, and nothing is evicted, since the archive may be
# the only forensic record of a suspected in-box compromise.
_MAX_ENV = "LEARNING_TAINT_QUARANTINE_MAX"
_MAX_DEFAULT = 10


def quarantine_cap() -> int:
    """How many tainted trees the lane will hold; shared by the writer and the queue page so
    they agree."""
    return env_int(_MAX_ENV, _MAX_DEFAULT)


def held_archives(quarantine_dir: Path) -> int:
    """How many tainted trees the directory holds, counted by archive (an archive whose
    manifest failed still spends a slot). Shared by `preserve_tainted_tree` and the queue page.

    A missing directory holds none; an unlistable one raises. `iterdir`, not `glob`, because
    `Path.glob` swallows `PermissionError` and answers "empty"."""
    if not quarantine_dir.is_dir():
        return 0
    return sum(1 for p in quarantine_dir.iterdir() if p.name.endswith(".tar.gz"))


def _archive_tree(wt: Path, dest: Path) -> None:
    """Write `wt` to `dest` as a gzipped tar.

    An archive rather than a move so the artifact is inert: with `dereference=False` a symlink
    is stored as metadata, so nothing walking the host (`grep -r`, an indexer, a backup) can
    follow it. A moved worktree would keep live links on the host.
    """
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(wt, arcname=wt.name)


def _tree_verdict(wt: Path) -> dict:
    """The scrub verdict, which lives outside the tree and so must be copied explicitly. `{}`
    rather than an absent key when there is none, so a skipped scan can't read as clean."""
    p = verdict_path(wt)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _manifest(
    wt: Path, archive: Path, *, batch_id: str, branch: str, label: DrainLabel, taint: RunTainted,
) -> dict:
    # `__context__` is the work's own failure, which the taint outranked. Recorded explicitly,
    # since the traceback is gone once the tree is.
    cause = taint.__context__
    return {
        "batch_id": batch_id,
        "branch": branch,
        "label": label.value,
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
    label: DrainLabel,
    taint: RunTainted,
) -> Path | None:
    """Archive a tainted worktree before its caller destroys it. Returns the archive path,
    or None if nothing was preserved.

    Never raises: a failure to quarantine must not mask the taint. Every outcome is logged,
    since a silent failure would look like a tree that was never tainted.
    """
    archived: Path | None = None
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        held = held_archives(quarantine_dir)
        cap = quarantine_cap()
        if held >= cap:
            _logger.warning(
                f"{label}: {held} quarantined tree(s) already held at "
                f"{quarantine_dir} (cap {cap}, {_MAX_ENV}) — NOT preserving {wt}. The "
                f"existing artifacts are untouched; clear them by hand once triaged."
            )
            return None
        archive = quarantine_dir / f"{batch_id}.tar.gz"
        try:
            _archive_tree(wt, archive)
        except BaseException:
            # A half-written tarball is not evidence and would spend a cap slot.
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
        _logger.warning(
            f"{label}: tainted worktree preserved at {archive} "
            f"({len(taint.findings)} finding(s), manifest {manifest.name})"
        )
        return archive
    except Exception as e:  # noqa: BLE001 — the taint outranks any failure to preserve it
        # Tell the operator what actually survived.
        residue = (
            f"the archive at {archived} survives, but WITHOUT its manifest"
            if archived is not None
            else "the tree is about to be destroyed and this taint's evidence is being lost"
        )
        _logger.error(f"{label}: FAILED to quarantine the tainted worktree {wt}: {e!r} — {residue}")
        return None
