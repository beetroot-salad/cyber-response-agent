"""A real run's session store, created and found again, addressed ONLY through the owner
(#1077, the session-store leftover of D7).

NOT A TEST MODULE (the leading underscore keeps pytest from collecting it). It is the payload
`test_1077_rename_proof.py` runs in a subprocess, against a tree whose `_run_paths.py` has had
the sessions directory's name, or the store's suffix, or both, rewritten to something else.

Nothing in this file spells either name, so it keeps working under any rename. What it drives:

1. A REAL run through the real driver (`drive`, the e2e replay harness) with NO injected store
   factory — so the store is opened by `driver._default_store_factory`, the one production
   uses, and the case pointer is written by the driver itself.
2. The RESUME door: `branch.open_source_store(run_dir)` — the store factory a resumed run is
   handed (`branch.store_factory_for`) is exactly this call, and it re-derives the store's path
   from the pointer's case id before it opens anything.

Both must land on the owner's answer — `RunPaths.session_db(runs_base, case_id)` — and the
filesystem must hold nothing else: a store module that composes the path out of names it
remembers creates its store where the owner does not say, and this reports that as a store
nowhere near the owner's path, rather than, as in production, a rename that silently leaves
every future run writing to the old directory.

Run as `python -m defender.tests._rename_proof_1077_session <work dir>`.
"""
from __future__ import annotations

import sys
from pathlib import Path

from defender import _run_paths
from defender._run_paths import RunPaths
from defender.runtime import branch, session_store
from defender.tests.e2e._replay_harness import GOLDEN, ReplayFn, Turn, drive, materialize


def _entries(path: Path) -> list[str]:
    return sorted(p.name for p in path.iterdir())


def main(root: Path) -> int:
    runs_base = root / "runs"
    run_dir = materialize(runs_base, GOLDEN)
    owner = RunPaths(run_dir)
    sessions = owner.sessions_dir(runs_base)
    print(f"SESSIONS_DIR_SEEN={sessions.name}", flush=True)
    # Say which tree this actually loaded, first — so a caller can tell "the store went to the
    # wrong place" apart from "the subprocess imported the real package and renamed nothing".
    # Read off the owner BY NAME: this file never holds either value itself.
    for name in ("SESSIONS_DIRNAME", "SESSION_DB_SUFFIX"):
        print(f"{name}={getattr(_run_paths, name)}", flush=True)

    summary = drive(run_dir, run_id="rename-proof-session", main=ReplayFn([
        Turn(text="Nothing to do; stopping."),
    ]))
    assert summary.get("truncated_by") is None, (
        f"session store: the run did not reach its own end ({summary}) — a store-setup "
        "failure ends a run as truncated_by='store' before a single turn")
    case_id = summary["case_id"]
    want = owner.session_db(runs_base, case_id)

    # WHERE THE RUN CREATED ITS STORE: the owner's path, and nowhere else beside the runs base.
    created = Path(str(summary.get("store_path")))
    assert created == want, (
        f"session store: the run created its store at {created}, but the owner names {want} — "
        "the store module composed the path itself")
    assert want.is_file(), f"session store: nothing on disk at the owner's path {want}"
    assert _entries(root) == sorted([runs_base.name, sessions.name]), (
        f"session store: the run wrote beside its runs base outside the owner's sessions dir: "
        f"{_entries(root)}")
    assert session_store.resolve_store_path(run_dir) == want, (
        "session store: the run's case pointer does not name the owner's path")

    # WHERE A RESUME FINDS IT: the store a sibling forks into, derived from the pointer alone.
    source = branch.open_source_store(run_dir)
    try:
        assert source.path == want, (
            f"session store: a resume opened {source.path}, but the owner names {want}")
        # The RIGHT database, not an empty one conjured at a well-formed path: the source
        # run's own main session is in it.
        assert session_store.main_session_id(source), (
            "session store: a resume found a store holding no main session")
    finally:
        source.close()
    assert sorted(p.name for p in sessions.iterdir() if p.name.startswith(want.name)), (
        "session store: the owner's store file vanished")
    assert all(p.name.startswith(want.name) for p in sessions.iterdir()), (
        f"session store: a second store appeared beside the run's own: {_entries(sessions)}")

    print("SESSION ROUNDTRIP OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
