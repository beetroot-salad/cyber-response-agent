"""#1412: loopback stand-ins and readers for the proxy's framed reply. A scripted raw-socket server
(an upstream that sends exactly what a case needs, or a proxy that sends chosen frames), a reader
that leaves the proxy's response unread, and builders for the format's names in
`defender.kit.proxy_client`, imported at call time so a missing name fails one case, not collection."""
from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from defender.kit.proxy_client import proxy_call
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH

MIB = 1024 * 1024
DEFAULT_LIMIT = 8 * MIB
JSON = {"Content-Type": "application/json"}


def fmt() -> Any:
    """The format's owner, read at call time."""
    import defender.kit.proxy_client as owner

    return owner


def final_record(status: int | None = 200, **over: Any) -> Any:
    """A `FinalRecord` (every field given): a clean 200 that reached the system unless `over`
    says otherwise."""
    fields = {"status": status, "headers": {}, "fault": None, "detail": None, "system_side": False,
              "sent": True, "body_whole": True, "reader_fault": False} | over
    return fmt().FinalRecord(**fields)


def decoded(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    """(the body frames joined, the final record's fields) of the framed reply `raw`."""
    reply = fmt().decode_reply(raw)
    return b"".join(reply.chunks), T.fields_of(reply.final)


def borrowed(url: str) -> int:
    """Worker threads the served proxy has lent out right now (`H.GAUGE_PATH`)."""
    with httpx.Client(trust_env=False, timeout=30) as client:
        return client.get(url + H.GAUGE_PATH).json()["borrowed"]


def doc(target: str, *, method: str = "GET", timeout_sec: float | None = None) -> dict[str, Any]:
    return {"system": "identity", "method": method, "url": target, "headers": {}, "body": None} | (
        {} if timeout_sec is None else {"timeout_sec": timeout_sec})


@contextlib.contextmanager
def unread(url: str, tok: str, request: dict[str, Any]) -> Iterator[httpx.Response]:
    """The proxy's response with its head received and its body left unread."""
    with httpx.Client(trust_env=False, timeout=60) as client, client.stream(
            "POST", url + PROXY_PATH, headers={"Authorization": f"Bearer {tok}"}, json=request) as response:
        yield response


def raw_post(url: str, tok: str, request: dict[str, Any]) -> httpx.Response:
    with httpx.Client(trust_env=False, timeout=60) as client:
        return client.post(url + PROXY_PATH, headers={"Authorization": f"Bearer {tok}"}, json=request)


def call(url: str, tok: str, target: str, *, method: str = "GET", timeout_sec: int = 5) -> Any:
    return proxy_call(url, tok, system="identity", method=method, url=target, timeout_sec=timeout_sec)


def until(done: Callable[[], bool], within: float) -> bool:
    limit = time.monotonic() + within
    while time.monotonic() < limit:
        if done():
            return True
        time.sleep(0.02)
    return done()


class Scripted:
    """A loopback server that reads each request's head, then runs `script(conn)`. `hung_up` is
    set once the peer has closed its side of the connection (a send fails or a read ends)."""

    def __init__(self, script: Callable[[socket.socket], None]) -> None:
        self.hung_up = threading.Event()
        self._script = script
        self._conns: list[tuple[socket.socket, threading.Thread]] = []
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.url = f"http://127.0.0.1:{self._srv.getsockname()[1]}"
        self._acceptor = threading.Thread(target=self._serve, daemon=True)
        self._acceptor.start()

    def _serve(self) -> None:
        with contextlib.suppress(OSError):
            while True:
                conn, _ = self._srv.accept()
                handler = threading.Thread(target=self._one, args=(conn,), daemon=True)
                self._conns.append((conn, handler))
                handler.start()

    def _one(self, conn: socket.socket) -> None:
        with conn:
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    more = conn.recv(65536)
                    if not more:
                        break
                    head += more
                else:
                    self._script(conn)
                while conn.recv(65536):  # the request's body, then the peer's close
                    pass
                self.hung_up.set()
            except OSError:
                self.hung_up.set()

    def close(self) -> None:
        """Stop accepting, end every connection and join every thread this server started."""
        with contextlib.suppress(OSError):
            self._srv.shutdown(socket.SHUT_RDWR)  # wakes the blocked accept
        self._srv.close()
        self._acceptor.join(5)
        for conn, handler in self._conns:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
            handler.join(5)


@contextlib.contextmanager
def scripted(script: Callable[[socket.socket], None]) -> Iterator[Scripted]:
    server = Scripted(script)
    try:
        yield server
    finally:
        server.close()


def head(status: int, length: int, reason: str = "OK", extra: bytes = b"") -> bytes:
    """An HTTP/1.1 response head declaring `length` body bytes."""
    return (b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n"
            % (status, reason.encode(), extra, length))


def chunked(*pieces: bytes) -> bytes:
    """`pieces` as the chunks of an HTTP chunked body, without its terminator."""
    return b"".join(b"%x\r\n%s\r\n" % (len(piece), piece) for piece in pieces)


def reply_head(content_type: str | None = None) -> bytes:
    """The head of a chunked 200 in the reply format's content type (or `content_type`)."""
    kind = fmt().REPLY_CONTENT_TYPE if content_type is None else content_type
    return b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n" % kind.encode()


@contextlib.contextmanager
def fake_proxy(payload: bytes, *, ended: bool, content_type: str | None = None) -> Iterator[str]:
    """A proxy stand-in answering with `payload` in the reply format's content type as one HTTP
    chunk, then either ending the HTTP body (`ended`) or closing with the body unfinished."""
    def script(conn: socket.socket) -> None:
        conn.sendall(reply_head(content_type))
        if payload:
            conn.sendall(chunked(payload))
        if ended:
            conn.sendall(b"0\r\n\r\n")
        conn.shutdown(socket.SHUT_WR)

    with scripted(script) as server:
        yield server.url
