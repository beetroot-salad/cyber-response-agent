"""The lab's endpoint-query service (#1391 O5, r6 O8, L4): an endpoint-security product's query API
over the lab's hosts, answered from live host state through a Docker daemon.

It is told what to serve and knows nothing of live or frozen: a Docker socket, the hosts it answers
for (`--hosts`, one name per line; each is a container on that daemon) and the containers it may
inspect (`--inspectable`, same shape, may be empty). Live: the lab daemon, both files the
inventory's hosts. Frozen (#1347): the frozen engine's daemon, the freeze's hosts, nothing
inspectable, so `container-inspect` answers 404 (#1347's named gap) and a replica's image name never
leaks.

Only these GET routes; anything else is 404, another method 405. Each runs one fixed command:

    GET /hosts                                         -> {"hosts": [{"name", "running"}]}
    GET /hosts/{host}/processes                        -> {"ps_output"}   (ps_argv, by name on PATH)
    GET /hosts/{host}/accounts                         -> {"entries"}     (cat /etc/passwd)
    GET /hosts/{host}/accounts/{user}/authorized-keys  -> {"path", "keys"} (getent, then cat)
    GET /hosts/{host}/files/sha256?path=...            -> {"sha256"}      (sha256sum)
    GET /hosts/{host}/packages                         -> {"packages"}    (dpkg-query)
    GET /containers/{id}                               -> {"name", "image"}

Status table (r4, r6): host not served 404; served but not running 503; a command that fails 503
(never 200 with empty output: a replica's `ps` shim without its tree exits non-zero); unknown user
404; no authorized_keys file 200 with no keys; bad `user` or `path` 400; a missing file 404.

`ps` runs by name so a frozen replica's shim (mounted on PATH) answers; its argv is the one
`lab-surface.json` names, the same one capture records and the shim matches.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, unquote, urlsplit

SURFACE = Path(os.environ.get("V2_LAB_SURFACE", Path(__file__).resolve().with_name("lab-surface.json")))
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@:+-]*$")
MAX_OUTPUT = 8 * 1024 * 1024
EXEC_TIMEOUT_S = 25


def ps_argv(surface_path: Path = SURFACE) -> list[str]:
    return list(json.loads(Path(surface_path).read_text())["ps_argv"])


class Unavailable(Exception):
    """The daemon or the container cannot answer (503)."""


class Docker(Protocol):
    def running(self, name: str) -> bool | None:
        """True/False for a container's run state, None when there is no such container."""

    def exec(self, name: str, argv: list[str]) -> tuple[int, bytes, bytes]:
        """Run `argv` in the container: (exit code, stdout, stderr)."""

    def inspect(self, name: str) -> dict | None:
        """The container's inspect document, None when there is none."""


# -- the Docker Engine API over its unix socket (no CLI in the image) ------------------------------


def _read_all(sock: socket.socket) -> bytes:
    chunks, size = [], 0
    while chunk := sock.recv(65536):
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_OUTPUT + 65536:
            raise Unavailable("the daemon's answer is too large")
    return b"".join(chunks)


def parse_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    """Status, headers (lower-cased) and body of a whole `Connection: close` HTTP/1.1 response,
    de-chunked when chunked."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise Unavailable("the daemon sent no complete response")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out, rest = bytearray(), body
        while True:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        body = bytes(out)
    return status, headers, body


def demux(stream: bytes) -> tuple[bytes, bytes]:
    """Split Docker's multiplexed exec stream (8-byte frame headers) into stdout and stderr."""
    out, err, i = bytearray(), bytearray(), 0
    while i + 8 <= len(stream):
        kind, size = stream[i], int.from_bytes(stream[i + 4:i + 8], "big")
        frame = stream[i + 8:i + 8 + size]
        (err if kind == 2 else out).extend(frame)
        i += 8 + size
    return bytes(out), bytes(err)


class SocketDocker:
    def __init__(self, path: str = "/var/run/docker.sock") -> None:
        self.path = path

    def _call(self, method: str, url: str, body: Any = None) -> tuple[int, bytes]:
        data = json.dumps(body).encode() if body is not None else b""
        request = (f"{method} {url} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(EXEC_TIMEOUT_S)
                sock.connect(self.path)
                sock.sendall(request)
                raw = _read_all(sock)
        except OSError as exc:
            raise Unavailable(f"docker daemon: {type(exc).__name__}: {exc}") from exc
        status, _, payload = parse_response(raw)
        return status, payload

    def inspect(self, name: str) -> dict | None:
        status, payload = self._call("GET", f"/containers/{quote(name, safe='')}/json")
        if status == 404:
            return None
        if status != 200:
            raise Unavailable(f"docker inspect {name}: HTTP {status}")
        return json.loads(payload)

    def running(self, name: str) -> bool | None:
        doc = self.inspect(name)
        return None if doc is None else bool(doc.get("State", {}).get("Running"))

    def exec(self, name: str, argv: list[str]) -> tuple[int, bytes, bytes]:
        status, payload = self._call("POST", f"/containers/{quote(name, safe='')}/exec",
                                     {"AttachStdout": True, "AttachStderr": True, "Tty": False, "Cmd": argv})
        if status != 201:
            raise Unavailable(f"docker exec {name}: HTTP {status} {payload[:200]!r}")
        exec_id = json.loads(payload)["Id"]
        status, stream = self._call("POST", f"/exec/{exec_id}/start", {"Detach": False, "Tty": False})
        if status != 200:
            raise Unavailable(f"docker exec start {name}: HTTP {status}")
        out, err = demux(stream)
        if len(out) > MAX_OUTPUT:
            raise Unavailable(f"{name}: output over {MAX_OUTPUT} bytes")
        status, payload = self._call("GET", f"/exec/{exec_id}/json")
        code = json.loads(payload).get("ExitCode") if status == 200 else None
        if code is None:
            raise Unavailable(f"docker exec {name}: no exit code")
        return int(code), out, err


# -- the query API ---------------------------------------------------------------------------------


class Answer(Exception):
    def __init__(self, status: int, body: dict) -> None:
        super().__init__(status)
        self.status, self.body = status, body


def _fail(status: int, why: str) -> Answer:
    return Answer(status, {"detail": why})


class Service:
    def __init__(self, docker: Docker, *, hosts: list[str], inspectable: list[str], argv: list[str]) -> None:
        self.docker, self.hosts, self.inspectable, self.ps = docker, list(hosts), set(inspectable), list(argv)

    def _host(self, host: str) -> str:
        if host not in self.hosts:
            raise _fail(404, f"host {host!r} is not enrolled")
        if not self.docker.running(host):
            raise _fail(503, f"host {host!r} is enrolled but not running")
        return host

    def _run(self, host: str, argv: list[str]) -> tuple[int, str, str]:
        code, out, err = self.docker.exec(host, argv)
        return code, out.decode(errors="replace"), err.decode(errors="replace")

    def _ok(self, host: str, argv: list[str]) -> str:
        code, out, err = self._run(host, argv)
        if code != 0:
            raise _fail(503, f"{argv[0]} on {host} exited {code}: {err.strip()[:300] or 'no stderr'}")
        return out

    def answer(self, method: str, target: str) -> tuple[int, dict]:
        try:
            return 200, self._route(method, target)
        except Answer as a:
            return a.status, a.body
        except Unavailable as exc:
            return 503, {"detail": str(exc)}

    def _route(self, method: str, target: str) -> dict:  # noqa: C901 - one flat route table
        parts = urlsplit(target)
        segments = [unquote(s) for s in parts.path.split("/")[1:]]
        query = parse_qs(parts.query)
        if method != "GET":
            raise _fail(405, "GET only")
        match segments:
            case ["hosts"]:
                return {"hosts": [{"name": h, "running": bool(self.docker.running(h))} for h in self.hosts]}
            case ["hosts", host, "processes"]:
                return {"ps_output": self._ok(self._host(host), self.ps)}
            case ["hosts", host, "accounts"]:
                out = self._ok(self._host(host), ["cat", "/etc/passwd"])
                return {"entries": [line for line in out.splitlines() if line and not line.startswith("#")]}
            case ["hosts", host, "accounts", user, "authorized-keys"]:
                return self._authorized_keys(host, user)
            case ["hosts", host, "files", "sha256"]:
                return self._sha256(host, query.get("path", []))
            case ["hosts", host, "packages"]:
                out = self._ok(self._host(host), ["dpkg-query", "-W", "-f=${Package} ${Version}\\n"])
                return {"packages": [line for line in out.splitlines() if line.strip()]}
            case ["containers", name]:
                if name not in self.inspectable:
                    raise _fail(404, f"no such container: {name}")
                doc = self.docker.inspect(name)
                if doc is None:
                    raise _fail(404, f"no such container: {name}")
                return {"name": str(doc.get("Name", "")).lstrip("/"),
                        "image": str(doc.get("Config", {}).get("Image", ""))}
        raise _fail(404, "no such route")

    def _authorized_keys(self, host: str, user: str) -> dict:
        if not SAFE_USERNAME_RE.match(user):
            raise _fail(400, f"refusing unsafe user value: {user!r}")
        self._host(host)
        code, out, _ = self._run(host, ["getent", "passwd", user])
        if code != 0 or not out.strip():
            raise _fail(404, f"user {user!r} not found on {host}")
        fields = out.strip().split(":")
        if len(fields) < 6:
            raise _fail(503, f"malformed passwd record for {user!r}")
        path = f"{fields[5]}/.ssh/authorized_keys"
        code, out, err = self._run(host, ["cat", path])
        if code != 0:
            if "No such file" in err:
                return {"path": path, "keys": []}
            raise _fail(503, f"cat {path} on {host} exited {code}: {err.strip()[:300]}")
        return {"path": path, "keys": [line for line in out.splitlines()
                                       if line.strip() and not line.startswith("#")]}

    def _sha256(self, host: str, paths: list[str]) -> dict:
        if len(paths) != 1:
            raise _fail(400, "exactly one path is required")
        path = paths[0]
        if not SAFE_PATH_RE.match(path) or any(s in (".", "..") for s in path.split("/")):
            raise _fail(400, f"refusing unsafe path value: {path!r}")
        self._host(host)
        code, out, err = self._run(host, ["sha256sum", "--", path])
        if code != 0:
            if "No such file" in err:
                raise _fail(404, f"{path!r} does not exist on {host}")
            raise _fail(503, f"sha256sum on {host} exited {code}: {err.strip()[:300]}")
        digest = out.split()[0] if out.strip() else ""
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise _fail(503, f"sha256sum on {host} printed no digest")
        return {"sha256": digest}


def make_handler(service: Service) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "endpoint-query"
        sys_version = ""

        def _reply(self) -> None:
            status, body = service.answer(self.command, self.path)
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _reply

    return Handler


def read_names(path: Path) -> list[str]:
    return [line.strip() for line in Path(path).read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The lab's endpoint-query service (#1391 r6 O8)")
    parser.add_argument("--hosts", type=Path, required=True, help="the hosts answered for")
    parser.add_argument("--inspectable", type=Path, required=True, help="the containers inspect may name")
    parser.add_argument("--socket", default="/var/run/docker.sock")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    hosts = read_names(args.hosts)
    if not hosts:
        print(f"{args.hosts} names no host: nothing to serve", file=sys.stderr)
        return 2
    service = Service(SocketDocker(args.socket), hosts=hosts, inspectable=read_names(args.inspectable),
                      argv=ps_argv())
    ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(service)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
