"""Real repository setup for the #1165 record and logging contract."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defender.tests.support.shared.contracts import _spec1077 as S


def run_at(tmp_path: Path, *, io: Any = None):
    """A fixture run's real `Run` in a fresh runs folder (#1187: the folder holds no
    `_tenant.json`, R1; the run is built by `Run.under`, which replaces `Run.for_tenant`, at a
    uuid4 id, which `RunId` alone admits)."""
    base = S.make_runs_base(tmp_path)
    directory = S.make_run_dir(base, RUN_ID)
    options = {} if io is None else {"io": io}
    return S.Run().under(base, directory.name, tenant_id=S.DEFAULT_TENANT_ID, **options)


#: The #1165 fixture run's id (a uuid4).
RUN_ID = "2c4e6a8b-1d3f-4b5a-9c7e-0f2a4b6c8d1e"


def writes(io: S.RecordingIo, path: Path) -> list[dict]:
    """Captured payloads of the real rooted writer, at this record only."""
    return [call for call in io.arguments("rooted_write")
            if Path(call["root"]) / call["name"] == path]
