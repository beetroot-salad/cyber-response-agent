"""#1546 (design-r9 "Session pointer"): a run's session pointer records its database relative to the run's folder, so a
run copied or moved elsewhere reads its own database only when that database goes with it, to the same place relative to
the run (as a bundle carries the tenant's `sessions/` beside its `runs/`). These carry it, for a test whose subject is a
copy or a move of a whole run or episode, not a run parted from its store.

The recorded path is resolved by the product's one resolver (`session_store.run_store_path`), never restated here. A
pointer that is not a readable JSON object naming a `store_path` (a fault a case planted) is carried as it is: nothing
is placed for it."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

#: The files a session database is, beside its own name (SQLite's write-ahead log and its index).
_SIDECARS = ("", "-wal", "-shm")


def _recorded(run_dir: Path) -> str | None:
    from defender.records import RunPaths

    pointer = Path(RunPaths(run_dir).session_pointer())
    try:
        body = json.loads(pointer.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    recorded = body.get("store_path") if isinstance(body, dict) else None
    return recorded if isinstance(recorded, str) and recorded else None


def carry_session_store(src_run: Path, dest_run: Path, *, move: bool = False) -> Path | None:
    """The database `src_run`'s pointer names (read before anything moves), placed at the same position
    relative to `dest_run`, its log and index with it; copied, or moved with `move`. Returns where it now is (None for a
    pointer naming none). A database already there (the same file, or one an earlier arm sharing it carried) is left."""
    from defender.records.session_store import run_store_path

    recorded = _recorded(src_run)
    if recorded is None:
        return None
    source, dest = run_store_path(Path(src_run), recorded), run_store_path(Path(dest_run), recorded)
    if dest.exists() or not source.is_file():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    for suffix in _SIDECARS:
        part = Path(f"{source}{suffix}")
        if part.exists():
            (shutil.move if move else shutil.copy2)(str(part), f"{dest}{suffix}")
    return dest


def carry_episode_sessions(src_episode: Path, dest_episode: Path) -> None:
    """Each arm run's database (`<episode>/runs/<arm>`, by its pointer beside it) copied to the same position relative to
    the arm's copy under `dest_episode` (a whole-episode copy made beside it)."""
    runs = Path(src_episode) / "runs"
    for pointer in sorted(runs.glob("*.session-pointer.json")) if runs.is_dir() else []:
        arm = pointer.name.removesuffix(".session-pointer.json")
        carry_session_store(runs / arm, Path(dest_episode) / "runs" / arm)
