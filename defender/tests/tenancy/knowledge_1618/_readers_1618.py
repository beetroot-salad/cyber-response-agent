"""#1618 slice C machinery: the operator tools and the judge as readers of Forgejo's commit (K4, K5, F3, F4).

Slice-local helpers only; the shared machinery and the one FORCED seam list are `_support`. A tool is run with the one fetch seam
(`fetch=K.fetch_seam(t)`, the real child) and no `identity=`: its own process mints nothing (O8), counted here by watching
`ForgejoIdentity.token` in-process (the child is another process, so its mint is not seen).
"""
from __future__ import annotations

import contextlib
import shutil
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
    fetches: list[dict[str, Any]]
    minted: int


def run_tool(t: Any, tmp_path: Path, capsys: Any, main: Callable[..., Any], argv: list[str], **seams: Any) -> ToolRan:
    """`main(argv, directory=, fetch=, **seams)` in-process under a private temporary folder: its exit status
    (a `SystemExit` is read as one), stdout, stderr, what it left in the temporary folder, the git requests it made, each
    ask of the fetch seam and how many credentials this process minted (O8)."""
    from defender.learning.author.version_control.auth import ForgejoIdentity
    from defender.tests.support.tenancy._host1214 import counting_calls

    capsys.readouterr()
    served = len(t.server.seen)
    seam = seams.pop("fetch", None) or K.fetch_seam(t, tmp_path / "fetch-work")
    with private_tmp(tmp_path) as tmp, counting_calls(mint=ForgejoIdentity.token) as minted:
        try:
            rc = main(argv, directory=t.directory, fetch=seam, **seams)
        except SystemExit as stop:
            rc = stop.code if isinstance(stop.code, int) else 1
            if isinstance(stop.code, str):
                print(stop.code, file=sys.stderr)
        said = capsys.readouterr()
        return ToolRan(int(rc or 0), said.out, said.err, listing(tmp), len(t.server.seen) - served, seam.calls,
                       minted.counts["mint"])


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


class HelperStandIn:
    """The job helper's socket for `copy.make(commit=)`, the one thing the judge asks it (F3): a unix socket server on the
    job-socket wire (`job_socket.read_message`/`write_message`). It answers each ask by running the one fetch seam (the real
    child) into an owned destination under `root`, as the helper does: `ok` -> `{"path", "commit"}`; `refused <class> <reason>`
    -> a typed refusal (`job_socket.Refused`'s wire) with the reason and the folder removed. `requests` records `(name, fields)`."""

    def __init__(self, t: Any, root: Path, fetch: Callable[..., str]) -> None:
        import socket
        import threading

        self.t, self.fetch, self.copies = t, fetch, Path(root) / "helper-copies-1618"
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.folder = Path(tempfile.mkdtemp(prefix="hs1618-"))
        self.path = self.folder / "s"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        self.server.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        from defender import job_socket

        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                try:
                    asked = job_socket.read_message(conn)
                    name, fields = asked["request"], dict(asked["fields"])
                    self.requests.append((name, fields))
                    job_socket.write_message(conn, self._answer(name, fields))
                except (OSError, ValueError, KeyError):
                    continue

    def _answer(self, name: str, fields: dict[str, Any]) -> dict[str, Any]:
        if name != "copy.make":
            return {"refused": {"reason": f"not asked here: {name}", "code": "unknown-request"}}
        commit = fields.get("commit")
        dest = K.owned_dest(self.copies, "judge")
        line = self.fetch(self.t.tenant_id, dest, data_root=self.t.data_root, commit=commit)
        word, _, rest = line.partition(" ")
        if word == "ok":
            return {"ok": {"path": str(dest), "commit": rest.split()[0]}}
        shutil.rmtree(dest, ignore_errors=True)
        return {"refused": {"reason": rest.partition(" ")[2] or line, "code": "refused"}}

    def close(self) -> None:
        self.server.close()
        shutil.rmtree(self.folder, ignore_errors=True)


@contextlib.contextmanager
def helper_socket(t: Any, root: Path, monkeypatch: Any, fetch: Callable[..., str] | None = None) -> Iterator[HelperStandIn]:
    """A `HelperStandIn` the process's job-socket environment names (the judge's in-container default path reads it)."""
    from defender import job_socket

    seam = fetch if fetch is not None else K.fetch_seam(t, Path(root) / "helper-fetch-work")
    helper = HelperStandIn(t, root, seam)
    monkeypatch.setenv(job_socket.SOCKET_ENV, str(helper.path))
    try:
        yield helper
    finally:
        helper.close()


__all__ = ["HelperStandIn", "K", "ToolRan", "helper_socket", "listing", "plant_run", "private_tmp", "run_tool"]
