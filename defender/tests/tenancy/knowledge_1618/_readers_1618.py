"""#1618 slice C machinery: the operator tools and the judge as readers of Forgejo's commit (K4, K5, F3, F4).

Slice-local helpers only; the shared machinery is `_support`. Seams for names the design leaves unnamed (FORCED):
- every operator tool's `main(argv, *, directory=None, identity=None)` takes `identity=` (the credential the fetch child
  would mint), so a test reaches the fake issuer in-process; `identity=None` is production (the tool calls the child).
- `grade_episode(..., knowledge_copy=<callable(commit) -> Path>)`: how a job-lane judge asks the helper for a copy of
  `commit` (the helper's `copy.make(commit=)`); a refusal is the callable raising.
- `job_host.main(..., fetch=<callable(tenant_id, dest, commit|None) -> commit>)` stands in for the helper spawning the
  fetch child (the helper holds no credential, O8).
"""
from __future__ import annotations

import contextlib
import sys
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.tenancy.knowledge_1618 import _support as K


@contextlib.contextmanager
def private_tmp(root: Path) -> Iterator[Path]:
    """Point the process's temporary folder at `root/tmp` for the block: whatever a tool made there and left shows."""
    folder = Path(root) / "tmp-1618"
    folder.mkdir(parents=True, exist_ok=True)
    before = tempfile.tempdir
    tempfile.tempdir = str(folder)
    try:
        yield folder
    finally:
        tempfile.tempdir = before


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in Path(folder).iterdir()) if Path(folder).is_dir() else []


@dataclass
class ToolRan:
    rc: int
    out: str
    err: str
    left: list[str]
    requests: int


def run_tool(t: Any, tmp_path: Path, capsys: Any, main: Callable[..., Any], argv: list[str], **seams: Any) -> ToolRan:
    """`main(argv, directory=, identity=, **seams)` in-process under a private temporary folder: its exit status
    (a `SystemExit` is read as one), stdout, stderr, what it left in the temporary folder, and the git requests it made."""
    capsys.readouterr()
    served = len(t.server.seen)
    with private_tmp(tmp_path) as tmp:
        try:
            rc = main(argv, directory=t.directory, identity=t.vault.identity(), **seams)
        except SystemExit as stop:
            rc = stop.code if isinstance(stop.code, int) else 1
            if isinstance(stop.code, str):
                print(stop.code, file=sys.stderr)
        said = capsys.readouterr()
        return ToolRan(int(rc or 0), said.out, said.err, listing(tmp), len(t.server.seen) - served)


def plant_run(t: Any, commit: str | None) -> str:
    """A finished run folder `<T>/runs/<id>`, stamped for the tenant, with its host-held knowledge record naming `commit`
    (`fresh`); return the run's id."""
    import json

    from defender.records import RunPaths
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as P

    base = K.tenant_root(t) / "runs"
    base.mkdir(parents=True, exist_ok=True)
    run = P.source_run(base)
    (run / "provenance.json").write_text(json.dumps(T.provenance_record(tenant_id=t.tenant_id)), encoding="utf-8")
    record = {"kind": "fresh", "commit": commit, "reason": None}
    Path(RunPaths(run).knowledge_source()).write_text(json.dumps(record), encoding="utf-8")
    return run.name


__all__ = ["K", "ToolRan", "listing", "plant_run", "private_tmp", "run_tool"]
