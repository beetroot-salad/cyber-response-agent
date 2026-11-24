"""#1546 (L5, `e2e/test_1344_learning_replay.py`): a stored source bundle whose session database is as a store of another
format version leaves it, and the reads of that version. The source exists only in the store (r10, A-O1), so a source of
another version is a stored bundle that holds one. Members are tenant-relative, as the job's packer lays them out; the
database is found by the run's case id beside `runs/` (`_jobs1342.session_db`), never by the pointer's recorded path."""
from __future__ import annotations

import io
import json
import sqlite3
import tarfile
from pathlib import Path

#: The format version current code refuses (any other than the one it writes).
OTHER_VERSION = 99


def session_db_in(tenant_dir: Path, investigation: str) -> Path:
    """The investigation's session database in an extracted bundle (`tenant_dir`: its tenant folder), by its case id."""
    from defender.tests.support.jobs._jobs1342 import session_db

    runs = tenant_dir / "runs"
    case = json.loads((runs / f"{investigation}.session-pointer.json").read_text(encoding="utf-8"))["case_id"]
    path = session_db(runs, case)
    assert path.is_file(), f"premise: the run's session database is in its bundle, at {path}"
    return path


def unpack(body: bytes, dest: Path) -> Path:
    """`body` (a bundle) extracted under `dest`, its tenant folder; returns `dest`."""
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as packed:
        packed.extractall(dest, filter="data")
    return dest


def store_version(body: bytes, investigation: str, work: Path) -> int:
    """The `user_version` of the investigation's session database held in the bundle `body` (extracted under `work`)."""
    conn = sqlite3.connect(session_db_in(unpack(body, work), investigation))
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def of_another_version(body: bytes, investigation: str, work: Path) -> bytes:
    """The bundle `body` with its session database's `user_version` set to `OTHER_VERSION`, every other member as it was
    (a member sqlite folded into the database file on close, a write-ahead log, is gone; the file holds what it held)."""
    from defender.tests.support.jobs._evidence_flows1546 import members, pack

    tenant_dir = unpack(body, work)
    conn = sqlite3.connect(session_db_in(tenant_dir, investigation))
    try:
        conn.execute(f"PRAGMA user_version = {OTHER_VERSION}")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # into the database file itself: the bundle holds that file
    finally:
        conn.close()
    return pack({name: (tenant_dir / name).read_bytes() for name in members(body) if (tenant_dir / name).is_file()})
