"""Real repository setup for the #1165 record and logging contract."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defender.tests.support.shared.contracts import _spec1077 as S


def run_at(tmp_path: Path, *, io: Any = None):
    base = S.make_runs_base(tmp_path)
    S.plant_tenant_record(base)
    directory = S.make_run_dir(base, "run-1165")
    options = {} if io is None else {"io": io}
    return S.Run().for_tenant(S.DEFAULT_TENANT_ID, directory.name,
                              runs_base=base, **options)


def writes(io: S.RecordingIo, path: Path) -> list[dict]:
    """Captured payloads of the real rooted writer, at this record only."""
    return [call for call in io.arguments("rooted_write")
            if Path(call["root"]) / call["name"] == path]
