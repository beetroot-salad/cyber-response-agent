"""#1170: a job socket the test owns, for the #1344 learning-entry suites that drive `job_entry.main`/`post_step.main` in
process: inside the job container (A6) an entry with no job socket does nothing, so each run is handed one.

`SocketStandIn(tenant, launch=..., answers=...)` serves `defender.job_socket`'s wire (one request per connection) on a
unix socket under `/tmp` (pytest's `tmp_path` overruns a unix socket's 108 bytes). It answers `launch` with the facts it was
given, each request named in `answers` by calling it with the request's fields (a `job_socket.Refused` it raises is sent as
the typed refusal), and refuses every other request `unknown-request`. Every request is kept in `asked`, in order.

It injects inputs and records calls; it decides nothing the entries' tests are about. The helper's own answers (its
policy) are pinned over the real helper in `tests/jobs/test_job_helper_learning.py` and
`tests/jobs/test_learning_container_entry.py`. `copy_make(tenant_id, pin=)` is the answer `copy.make(commit=)` gets from
the real helper's side (#1618 F3, K5: `export.materialise` merged into it): a copy of that commit's (else `main`'s)
`agent/` and `settings/`, made by the product's fetch from the tenant's Forgejo repository into a fresh folder, refused
`delivery` when it cannot be; with `pin` (#1546 r10 (a), owner decision H1) a `commit=` other than the pin is refused
`not-for-kind`, naming it, before any fetch, as the real helper refuses it."""
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from defender import job_socket


class SocketStandIn:
    """A job socket answering `launch` and `answers`; use as a context manager (it serves until closed)."""

    def __init__(self, tenant: str, *, launch: Mapping[str, Any] | None = None,
                 answers: Mapping[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
                 forward: Callable[..., dict[str, Any]] | None = None) -> None:
        self.launch = {"tenant": tenant, "tenant_state": "active", "proxy_url": None, **(launch or {})}
        self.answers = dict(answers or {})
        #: A job-socket client (`ask(name, **fields)`, e.g. a real helper's `PostStepHelper.ask`) every request this stand-in
        #: has no answer for is passed to; its answer or typed refusal is returned as it came. Decides nothing here.
        self.forward = forward
        self.asked: list[tuple[str, dict[str, Any]]] = []
        self._folder = Path(tempfile.mkdtemp(prefix="j", dir="/tmp"))
        self.path = self._folder / "job.sock"
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(self.path))
        self._listener.listen(16)
        self._listener.settimeout(0.2)
        self._closing = threading.Event()
        self._thread = threading.Thread(target=self._accept, name="socket-standin", daemon=True)
        self._thread.start()

    def environ(self) -> dict[str, str]:
        """This process's environment with the job socket named, as the entry reads it. Not the container's whole
        environment: a caller that needs that filters this process's environment as the helper does
        (`job_host._container`)."""
        return {**os.environ, **self.environ_delta()}

    def environ_delta(self) -> dict[str, str]:
        """What a job container's environment adds for its socket."""
        return {job_socket.SOCKET_ENV: str(self.path)}

    def requests(self, name: str) -> list[dict[str, Any]]:
        return [fields for asked, fields in self.asked if asked == name]

    def _accept(self) -> None:
        while not self._closing.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(30)
            try:
                message = job_socket.read_message(conn)
            except (OSError, ValueError):
                return
            name = str(message.get("request")) if isinstance(message, dict) else ""
            fields = message.get("fields") if isinstance(message, dict) and isinstance(message.get("fields"), dict) else {}
            self.asked.append((name, dict(fields)))
            try:
                if name == "launch":
                    answer: Any = {"ok": dict(self.launch)}
                elif name in self.answers:
                    answer = {"ok": self.answers[name](dict(fields))}
                elif self.forward is not None:
                    answer = {"ok": self.forward(name, **fields)}
                else:
                    raise job_socket.Refused(f"the stand-in answers no {name!r}", "unknown-request")
            except job_socket.Refused as refused:
                answer = {"refused": {"code": refused.code, "reason": str(refused)}}
            with contextlib.suppress(OSError):
                job_socket.write_message(conn, answer)

    def close(self) -> None:
        self._closing.set()
        self._thread.join(timeout=5)
        self._listener.close()
        shutil.rmtree(self._folder, ignore_errors=True)

    def __enter__(self) -> SocketStandIn:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class StubPort:
    """The tick's store where the case does not look at it (`stubbed_port`): any use of it is a failure of the case, which
    stubbed the tick that would have used it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the case stubbed its tick, yet the tick's store was used: {name}")


@contextlib.contextmanager
def stubbed_port() -> Iterator[StubPort]:
    """For a case that stubs the post-step's tick and whose subject is not the store (#1487 Amendment 1: `post_step.main`
    hands its tick `JobContainer.tick_store()`, whose construction asks the helper for the settings, and this stand-in has
    no helper behind it): the port is a `StubPort` for the length of the run. The real port is the conformance suite's,
    and a case that wants it forwards to a real helper (`SocketStandIn(forward=)`) instead."""
    from unittest import mock

    from defender.learning.branch.container import JobContainer

    stub = StubPort()
    with mock.patch.object(JobContainer, "tick_store", return_value=stub, create=True):
        yield stub


def copy_make(tenant_id: str, remote: Path | str | None = None, *,
              pin: str | None = None) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """`copy.make(commit=)` answered as the helper's side does it (#1618 F3): the product's fetch
    (`_fetch_standin_1618.fetch_line`) of `commit` (else `main`) from the tenant's bare `remote` (default: the data root's
    served remote) into a fresh folder this stand-in owns, answered `{path, commit}`; refused `delivery`, naming why,
    when the fetch is refused or brings another commit. `pin`: the claim's `knowledge_commit` (#1546 r10 (a), H1); a
    `commit=` that is not it is refused `not-for-kind`, naming the commit, before any fetch. A `world=` (a sibling's copy)
    is not this answer's: it is refused `unknown-request` (the real helper's answer is pinned over the real helper)."""
    from defender.tests.support.tenancy._fetch_standin_1618 import fetch_line

    def answer(fields: dict[str, Any]) -> dict[str, Any]:
        from defender import tenancy
        from defender.tenancy import run_knowledge

        if fields.get("world") is not None:
            raise job_socket.Refused("this stand-in makes no sibling's copy", "unknown-request")
        commit = fields.get("commit")
        if pin is not None and commit is not None and commit != pin:
            raise job_socket.Refused(f"copy.make(commit={commit}) is not this job's pin", "not-for-kind")
        dest = Path(tempfile.mkdtemp(prefix="copy-make-"))
        line = fetch_line(tenant_id, dest, data_root=tenancy.resolve_data_root(), commit=commit,
                          remote=None if remote is None else Path(str(remote)))
        report = run_knowledge.read_publish_report(line)
        if report.kind != run_knowledge.OK or (commit is not None and report.commit != commit):
            shutil.rmtree(dest, ignore_errors=True)
            why = report.reason if report.kind != run_knowledge.OK else f"the fetch brought {report.commit}"
            raise job_socket.Refused(f"the knowledge of {commit or 'main'} could not be fetched: {why}", "delivery")
        return {"commit": report.commit, "path": str(dest)}

    return answer


def passes(tenant_id: str, reads: tuple[str, ...], *, directory: Any, proxy_url: str | None, signer: Any = None,
           transport: Any = None) -> tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]:
    """The helper's half of a job's passes (#1170 O5): the proxy's address its launch facts name, and its `pass` answer,
    each pass signed anew by the helper's own mint (`PassMint`) over the read grant `reads`, one it cannot sign refused
    `sign-fault` as the helper's `answer_pass` refuses it. The helper's first pass at claim is not signed here: a job
    whose first pass cannot be signed is refused before its container (`tests/jobs/test_job_helper_learning.py`)."""
    from defender.credential_proxy import signing_access
    from defender.job_host._session import PassMint, Signing

    signer, address = signing_access(tenant_id, directory=directory, signer=signer, proxy_url=proxy_url,
                                     transport=transport)
    mint = PassMint(Signing(signer, address, tenant_id), tuple(reads))

    def answer(fields: dict[str, Any]) -> dict[str, Any]:
        try:
            return mint.mint(str(fields["id"]))
        except Exception as failed:  # noqa: BLE001 — as the helper's `answer_pass`
            raise job_socket.Refused(f"the pass could not be signed: {type(failed).__name__}: {failed}",
                                     "sign-fault") from None

    return address, answer


def handed_records(directory: Any, tenant: str) -> dict[str, Any]:
    """The `records` launch fact the real helper hands a container (#1366 O6, #1170 A6): the tenant's current records in
    `directory` (the scene's), read as the helper reads them at the job's start."""
    from defender.tenancy import requested_tenant_id

    return directory.current_records(requested_tenant_id(tenant)).as_wire()
