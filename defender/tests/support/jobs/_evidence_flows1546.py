"""#1546 slice SD machinery: the worker-level flows over the new rows (`jobs.claims`, `jobs.staged_facts`,
`jobs.uploads`) and the opened-paths audit that also sees SQLite. NO test functions.

Seam picks (names the design leaves open; the code stage may rename them here, in one place):
- table `jobs.claims` (`token`, `tenant_id`, `kind`, one reference column per kind: `investigation_id`,
  `learning_job_id`, `host_request_id` (readiness, adoption, drain), `hold_tenant_id` (post-step), `launch`, `inputs`);
- `jobs.staged_facts (token, name, body, staged_at)`, `jobs.uploads (token, object, size, sha256, wrapped_key, status,
  scrub, accepted_at, created_at)`; owner columns `evidence_state`, `scrub` (investigations).
- staged fact bodies: the spellings of `STARTED`/`knowledge`/`outcome`/`page`/`arms`/`arm/<id>`/`result`/`refused/<name>`
  below. Only the names the design spells (`started`, `knowledge`, `outcome`, `page` = `rendered|render_failed|none`,
  `arms`, `arm/<id>` = `{scrub, page}`, `result`, `refused/<name>{reason}`, findings `screened|refused`) are the
  design's; the inner field spellings are picks.
The worker, whatever the kind, reads only these rows: a stand-in `Staging` writes them under the claim row the worker's
own claim made, so a missing seam is a red at `Staging.__call__` (kept on `.raised`), not a vacuous pass."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tarfile
import os
import subprocess
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.shared._postgres1339 import execute

from defender.tests.support.evidence._facts1546 import (  # noqa: E402, F401 — re-exported: one owner of the fact bodies
    EPISODE_PAGE,
    KNOWLEDGE,
    REFERENCE,
    RUN_PAGE,
    STARTED,
    arm_page,
    screened,
    staged_inv_outcome,
    staged_learning_outcome,
)

ROOTS, INPUTS, SPOOL = ".job-roots", ".job-inputs", ".job-spool"
inv_outcome = staged_inv_outcome
learning_outcome = staged_learning_outcome


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- the rows ---------------------------------------------------------------------------------------------------------

def claims_of(dsn: str, kind: str, reference: str) -> list[str]:
    """Every claim token naming `reference` (an owner id, a request id, or a tenant id for a post-step)."""
    column = REFERENCE[kind]
    found = execute(dsn, f"SELECT token FROM jobs.claims WHERE kind = %s AND {column} = %s",  # noqa: S608
                    (kind, reference))
    return [r[0] for r in found]


def claim_of(dsn: str, kind: str, reference: str) -> str | None:
    found = claims_of(dsn, kind, reference)
    assert len(found) <= 1, f"{len(found)} claims name {kind} {reference}"
    return found[0] if found else None


def claim_row(dsn: str, token: str) -> dict[str, Any] | None:
    cols = ("token", "tenant_id", "kind", "investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id",
            "inputs")
    found = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.claims WHERE token = %s", (token,))  # noqa: S608
    return dict(zip(cols, found[0], strict=True)) if found else None


def stage_fact(dsn: str, token: str, name: str, body: Any) -> None:
    execute(dsn, "INSERT INTO jobs.staged_facts (token, name, body, staged_at) VALUES (%s, %s, %s::jsonb, now())",
            (token, name, json.dumps(body)))


def facts(dsn: str, token: str) -> dict[str, Any]:
    return dict(execute(dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (token,)))


def stage_upload(dsn: str, token: str, obj: str, data: bytes | None, *, status: str | None = None,
                 scrub: str | None = None) -> None:
    """An upload row as the helper leaves it: `uploaded` with data, `refused` with none (the PUT that failed), unless `status`
    says. Every row carries the size, digest and wrapped key it was inserted with `pending`, before the PUT (design: uploads)."""
    status = status or ("refused" if data is None else "uploaded")
    sent = data if data is not None else f"{token}/{obj}: the bytes whose PUT the store refused".encode()
    execute(dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, scrub, created_at) "
                 "VALUES (%s, %s, %s, %s, %s, %s, %s, now())",
            (token, obj, len(sent), sha(sent), f"wrapped:{obj}", status, scrub))


def accepted(dsn: str, token: str) -> list[str]:
    found = execute(dsn, "SELECT object FROM jobs.uploads WHERE token = %s AND accepted_at IS NOT NULL", (token,))
    return sorted(r[0] for r in found)


def owner(dsn: str, table: str, owner_id: str, *cols: str) -> tuple[Any, ...]:
    [found] = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.{table} WHERE id = %s", (owner_id,))  # noqa: S608
    return tuple(found)


def learning_jobs_of(dsn: str, investigation: str) -> int:
    [(n,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (investigation,))
    return int(n)


def attempts_of(dsn: str, investigation: str) -> list[tuple[str, str]]:
    """(id, stage) of every attempt of the investigation's alert, oldest first."""
    return [(str(i), s) for i, s in execute(
        dsn, "SELECT id, stage FROM jobs.investigations WHERE alert_id = (SELECT alert_id FROM jobs.investigations "
             "WHERE id = %s) ORDER BY attempt", (investigation,))]


# --- the stand-in helper ---------------------------------------------------------------------------------------------

def write_outside(files: dict[Path, bytes]) -> None:
    """Make files in a subprocess, so the test's own writes never read as the worker's opens."""
    code = ("import sys, pathlib\n"
            "for i in range(1, len(sys.argv), 2):\n"
            "    p = pathlib.Path(sys.argv[i]); p.parent.mkdir(parents=True, exist_ok=True)\n"
            "    p.write_bytes(bytes.fromhex(sys.argv[i + 1]))\n")
    subprocess.run([sys.executable, "-c", code, *[a for p, d in files.items() for a in (str(p), d.hex())]], check=True)


@dataclass
class Staging:
    """A worker's `*_argv` seam that plays the helper's staging. After the worker's claim (the claim row exists) it reads the
    token off `jobs.claims` for `kind`/`reference(launch)`, makes the claim's folders with a file each when `folders`,
    writes `plant` (path -> bytes, outside the audit) and stages `staged` (fact name -> body) and `objects` (name -> bytes
    uploaded, None refused) under that token, then returns `child(launch)`. `raised` keeps a fault so a case names a
    missing seam instead of reading the worker's `worker_error`."""

    dsn: str
    root: Path
    kind: str
    reference: Callable[[Any], str]
    child: Callable[[Any], list[str]]
    staged: dict[str, Any] = field(default_factory=dict)
    objects: dict[str, bytes | None] = field(default_factory=dict)
    folders: bool = False
    plant: Callable[[str], dict[Path, bytes]] | None = None
    before: Callable[[str], None] | None = None
    token: str | None = None
    inputs: Any = None
    raised: BaseException | None = None
    launches: list[Any] = field(default_factory=list)

    def __call__(self, launch: Any) -> list[str]:
        try:
            return self._launch(launch)
        except BaseException as fault:
            self.raised = fault
            raise

    def _launch(self, launch: Any) -> list[str]:
        self.launches.append(launch)
        self.token = claim_of(self.dsn, self.kind, self.reference(launch))
        assert self.token, f"the worker's claim of the {self.kind} wrote no claim row"
        self.inputs = (claim_row(self.dsn, self.token) or {}).get("inputs")
        if self.folders:
            write_outside({base / self.token / "left.txt": b"the helper's"
                           for base in (self.root / ROOTS, self.root / INPUTS, self.root / SPOOL)})
        if self.plant is not None:
            write_outside(self.plant(self.token))
        if self.before is not None:
            self.before(self.token)
        for name, body in self.staged.items():
            stage_fact(self.dsn, self.token, name, body)
        for obj, data in self.objects.items():
            stage_upload(self.dsn, self.token, obj, data)
        return self.child(launch)

    def assert_ran(self) -> None:
        assert self.raised is None, f"the stand-in helper's staging failed (a missing seam?): {self.raised!r}"
        assert self.token, "premise: the worker launched a child"


# --- the opened-paths audit, with SQLite --------------------------------------------------------------------------------

_watching: list[list[tuple[str, bool]]] = []


def _spelled(event: str, arg: Any) -> str | None:
    if not isinstance(arg, (str, bytes, os.PathLike)):
        return None
    text = os.fsdecode(arg)
    if event == "sqlite3.connect" and text.startswith("file:"):  # `records/session_store/_write.py` opens `file:///..?mode=rw`
        text = urllib.parse.unquote(urllib.parse.urlparse(text).path)
    return text


def _hook(event: str, args: tuple) -> None:
    if event in ("open", "sqlite3.connect") and _watching and args:
        path = _spelled(event, args[0])
        if path is not None:
            entry = (os.path.realpath(path), os.path.isdir(path))
            for seen in _watching:
                seen.append(entry)


sys.addaudithook(_hook)  # cannot be removed; records only while `audited` is open


@contextlib.contextmanager
def audited() -> Iterator[list[tuple[str, bool]]]:
    """Every `(real path, was a directory)` this process opens (`open`, `os.open`, `sqlite3.connect`), failed opens included."""
    seen: list[tuple[str, bool]] = []
    _watching.append(seen)
    try:
        yield seen
    finally:
        _watching.remove(seen)


def files_opened_under(seen: list[tuple[str, bool]], *bases: Path) -> list[str]:
    """The non-directory opens at or under any of `bases` (a directory open is a listing or a stat, not a read)."""
    real = [os.path.realpath(b) for b in bases]
    return sorted({p for p, is_dir in seen if not is_dir and any(p == b or p.startswith(b + os.sep) for b in real)})


def job_written_places(root: Path, *tenants: str) -> list[Path]:
    """Where a job's bytes live on the host: its per-claim roots, inputs and spool, and each tenant's own folder."""
    return [root / ROOTS, root / INPUTS, root / SPOOL, *(root / t for t in tenants)]


# --- the bundle oracle: tar+gzip of regular files (the design's "Objects per owner") --------------------------------------

def pack(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def members(bundle: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        return {m.name.removeprefix("./"): tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}  # type: ignore[union-attr]
