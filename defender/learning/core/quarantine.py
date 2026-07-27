from __future__ import annotations

import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from defender._env import env_int
from defender.learning.core.config import _log
from defender.runtime.scrub import RunTainted


# How many tainted trees may accumulate before the lane stops preserving them (#747, M4).
# A CAP, never a TTL: past it we refuse to write and say so, and nothing already written is
# evicted. A timer that deleted the only forensic record of a suspected in-box RCE would be
# the very bug this module exists to fix, just on a schedule.
_MAX_ENV = "LEARNING_TAINT_QUARANTINE_MAX"
_MAX_DEFAULT = 10


def _archive_tree(wt: Path, dest: Path) -> None:
    """Write `wt` to `dest` as a gzipped tar.

    `tarfile` at its default `dereference=False` is what makes the artifact INERT, and that
    is the whole reason this is an archive rather than a `mv` (#747): a symlink is stored as
    METADATA — the type flag plus the target string — and never followed. Nothing that walks
    the host afterwards (a `grep -r`, an editor indexer, a backup job) can deref a link that
    exists only as a tar member, so unpacking becomes a deliberate operator act. Relocating
    the worktree would have preserved a live, dereferenceable link on the host permanently,
    which moves the hazard rather than containing it.
    """
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(wt, arcname=wt.name)


def _manifest(
    wt: Path, archive: Path, *, batch_id: str, branch: str, label: str, taint: RunTainted,
) -> dict:
    # `__context__` is the work's own failure, which the taint outranked on its way out
    # (box.py's exception preference). It is the reason the batch was dying BEFORE the tree
    # was found tainted, and reading it off the traceback is exactly what the operator can
    # no longer do once the tree is gone — so it is recorded, not left to implicit chaining.
    cause = taint.__context__
    return {
        "batch_id": batch_id,
        "branch": branch,
        "label": label,
        "worktree": str(wt),
        "archive": archive.name,
        "quarantined_at": datetime.now(UTC).isoformat(),
        "taint": str(taint),
        "cause": repr(cause) if cause is not None else None,
        "findings": [
            {
                "path": str(f.path), "kind": f.kind, "filemode": f.filemode,
                "nlink": f.nlink, "target": f.target,
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
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(quarantine_dir.glob("*.tar.gz"))
        cap = env_int(_MAX_ENV, _MAX_DEFAULT)
        if len(existing) >= cap:
            _log(
                f"{label}: {len(existing)} quarantined tree(s) already held at "
                f"{quarantine_dir} (cap {cap}, {_MAX_ENV}) — NOT preserving {wt}. The "
                f"existing artifacts are untouched; clear them by hand once triaged."
            )
            return None
        archive = quarantine_dir / f"{batch_id}.tar.gz"
        _archive_tree(wt, archive)
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
        _log(
            f"{label}: FAILED to quarantine the tainted worktree {wt}: {e!r} — the tree is "
            "about to be destroyed and this taint's evidence is being lost"
        )
        return None
