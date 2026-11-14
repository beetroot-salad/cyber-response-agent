"""The job socket's server (#1170 H9): one thread accepting, one per connection, each request answered from the
registry by the job's kind.

The filesystem alone decides who may use it (#1469 S4): any connection that reaches the socket, 0600 in its 0700
folder, is answered. There is no caller check: under gVisor every host process looked like a container process to it,
and the daemon's process list needs the daemon's pid namespace and `ps`. The server records whether it ever accepted a
connection (`accepted`), which is how the helper tells a job that never reached its socket (D4)."""
from __future__ import annotations

import contextlib
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any

from defender.job_socket import Refused, read_message, write_message

from ._container import owner
from ._session import Registry, Session

_logger = logging.getLogger(__name__)

#: Seconds a connection may take to send its request.
_REQUEST_WAIT = 30.0


class Server:
    """Serves `session`'s socket at `path` until `close()`."""

    def __init__(self, session: Session, registry: Registry, path: Path) -> None:
        self._session, self._registry, self.path = session, registry, path
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(str(path))
            os.chmod(path, 0o600)
            uid, gid = owner(session)
            if os.geteuid() == 0 and (uid, gid) != (0, 0):
                os.chown(path, uid, gid)
            self._listener.listen(64)
        except BaseException:
            self._listener.close()
            raise
        self._listener.settimeout(0.2)
        self._closing = threading.Event()
        #: Set once any connection was accepted: the socket was reachable from where the job runs.
        self.accepted = threading.Event()
        self._thread = threading.Thread(target=self._accept, name="job-socket", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closing.set()
        self._thread.join(timeout=5)
        self._listener.close()
        with contextlib.suppress(OSError):
            self.path.unlink()

    def _accept(self) -> None:
        while not self._closing.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._closing.is_set():
                    return
                continue
            self.accepted.set()
            threading.Thread(target=self._serve, args=(conn,), name="job-socket-request", daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(_REQUEST_WAIT)
            try:
                request = read_message(conn)
                answer = self._answer(request)
                conn.settimeout(None)
                write_message(conn, answer)
            except (OSError, ValueError) as broken:
                _logger.info("job socket: a connection ended without an answer: %s", broken)

    def _answer(self, request: Any) -> dict[str, Any]:
        name = request.get("request") if isinstance(request, dict) else None
        fields = request.get("fields") if isinstance(request, dict) else None
        try:
            return {"ok": self._registry.answer(self._session, name, fields)}
        except Refused as refused:
            _logger.info("job socket: %s refused (%s): %s", name, refused.code, refused)
            return {"refused": {"code": refused.code, "reason": str(refused)}}
        except Exception as fault:  # noqa: BLE001 — one request's fault is its refusal, never the helper's end
            _logger.exception("job socket: %s faulted", name)
            return {"refused": {"code": "internal", "reason": f"{type(fault).__name__}: {fault}"}}
