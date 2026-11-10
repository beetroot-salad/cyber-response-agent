"""#1170: a job socket the test owns, for the #1344 learning-entry suites that drive `job_entry.main`/`post_step.main` in
process: inside the job container (A6) an entry with no job socket does nothing, so each run is handed one.

`SocketStandIn(tenant, launch=..., answers=...)` serves `defender.job_socket`'s wire (one request per connection) on a
unix socket under `/tmp` (pytest's `tmp_path` overruns a unix socket's 108 bytes). It answers `launch` with the facts it was
given, each request named in `answers` by calling it with the request's fields (a `job_socket.Refused` it raises is sent as
the typed refusal), and refuses every other request `unknown-request`. Every request is kept in `asked`, in order.

It injects inputs and records calls; it decides nothing the entries' tests are about. The helper's own answers (its
policy) are pinned over the real helper in `tests/jobs/test_job_helper_learning.py` and
`tests/jobs/test_learning_container_entry.py`. `materialise(tenant_id)` is the answer `export.materialise` gets from the
real helper's side: the tenant's export of the commit, materialised from its clone on the host (`materialise_export`),
refused `delivery` when it cannot be."""
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import tempfile
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from defender import job_socket


class SocketStandIn:
    """A job socket answering `launch` and `answers`; use as a context manager (it serves until closed)."""

    def __init__(self, tenant: str, *, launch: Mapping[str, Any] | None = None,
                 answers: Mapping[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None) -> None:
        self.launch = {"tenant": tenant, "tenant_state": "active", "proxy_url": None, **(launch or {})}
        self.answers = dict(answers or {})
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
        """This process's environment with the job socket named: the container's, as the entry reads it."""
        return {**os.environ, job_socket.SOCKET_ENV: str(self.path)}

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


def materialise(tenant_id: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """`export.materialise(commit=)` answered as the helper's side does it: the tenant's export of `commit` made from its
    clone on the host, or refused `delivery`."""

    def answer(fields: dict[str, Any]) -> dict[str, Any]:
        from defender import tenancy
        from defender.learning.author.version_control import DeliveryRefused, LockBusy, materialise_export

        tenant = tenancy.requested_tenant(tenancy.resolve_data_root(), tenant_id)
        try:
            export = materialise_export(tenant, str(fields.get("commit")))
        except (DeliveryRefused, LockBusy) as refused:
            raise job_socket.Refused(f"the export could not be materialised: {refused}", "delivery") from None
        return {"commit": export.commit, "path": str(export.path)}

    return answer
