"""The lab's endpoint-query service (#1391 O5, r6 O8, L4): an endpoint-security product's query API
over the lab's hosts, answered from live host state through a Docker daemon.

It is told what to serve and knows nothing of live or frozen: a Docker socket, the hosts it answers
for (`--hosts`, one name per line; each is a container on that daemon) and the containers it may
inspect (`--inspectable`, same shape, may be empty). Live: the lab daemon, both files the
inventory's hosts. Frozen (#1347): the frozen engine's daemon, the freeze's hosts, nothing
inspectable, so `container-inspect` answers 404 (#1347's named gap) and a replica's image name never
leaks.

Only these GET routes; anything else is 404, another method 405:

    GET /hosts                                         -> {"hosts": [{"name", "running"}]}
    GET /hosts/{host}/processes                        -> {"ps_output"}   (ps_argv, run in the host)
    GET /hosts/{host}/accounts                         -> {"entries"}     (/etc/passwd)
    GET /hosts/{host}/accounts/{user}/authorized-keys  -> {"path", "keys"} (/etc/passwd, then the file)
    GET /hosts/{host}/files/sha256?path=...            -> {"sha256"}
    GET /hosts/{host}/packages                         -> {"packages"}    (/var/lib/dpkg/status)
    GET /containers/{id or name}                       -> {"name", "image"}

Only the process list runs a command in the host (`ps`, by name on PATH, so a frozen replica's shim
answers; its argv is `lab-surface.json`'s, the one capture records and the shim matches). Every
other verb reads files through the daemon's archive API: nothing starts inside the host, so the
defender's own queries leave no process or file-access trace in the telemetry it investigates. A
symlink is followed inside the host's filesystem, at most `MAX_LINKS` times.

A host or container is named by id or name: the daemon resolves it, and the container's own name
is then checked against the list it must be on (`--hosts`, `--inspectable`).

Status table (r4, r6): host not served 404; served but not running 503; a command that fails 503
(never 200 with empty output: a replica's `ps` shim without its tree exits non-zero); unknown user
404; no authorized_keys file 200 with no keys; bad `user` or `path` 400; a missing file 404.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
import posixpath
import re
import socket
import sys
import tarfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, unquote, urlsplit

SURFACE = Path(os.environ.get("V2_LAB_SURFACE", Path(__file__).resolve().with_name("lab-surface.json")))
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@:+-]*$")
MAX_OUTPUT = 8 * 1024 * 1024
EXEC_TIMEOUT_S = 25
EXIT_CODE_WAIT_S = 5
MAX_LINKS = 8
DPKG_STATUS = "/var/lib/dpkg/status"


def ps_argv(surface_path: Path = SURFACE) -> list[str]:
    return list(json.loads(Path(surface_path).read_text())["ps_argv"])


class Unavailable(Exception):
    """The daemon or the container cannot answer (503)."""


class Docker(Protocol):
    def container(self, ref: str) -> dict | None:
        """The inspect document of the container `ref` names (id, id prefix or name), or None."""

    def exec(self, name: str, argv: list[str]) -> tuple[int, bytes, bytes]:
        """Run `argv` in the container: (exit code, stdout, stderr)."""

    def read(self, name: str, path: str) -> tuple[str, bytes | str] | None:
        """What is at `path` in the container's filesystem, without running anything in it:
        ("file", content), ("link", target), ("other", ""), or None when nothing is there."""


# -- the Docker Engine API over its unix socket (no CLI in the image) ------------------------------


class _UnixConnection(http.client.HTTPConnection):
    """The stdlib HTTP client over the daemon's unix socket."""

    def __init__(self, path: str) -> None:
        super().__init__("docker", timeout=EXEC_TIMEOUT_S)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.unix_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


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
        data = json.dumps(body).encode() if body is not None else None
        conn = _UnixConnection(self.path)
        try:
            conn.request(method, url, body=data, headers={"Content-Type": "application/json", "Connection": "close"})
            reply = conn.getresponse()
            payload = reply.read(MAX_OUTPUT + 65536 + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise Unavailable(f"docker daemon: {type(exc).__name__}: {exc}") from exc
        finally:
            conn.close()
        if len(payload) > MAX_OUTPUT + 65536:
            raise Unavailable("the daemon's answer is too large")
        return reply.status, payload

    def container(self, ref: str) -> dict | None:
        status, payload = self._call("GET", f"/containers/{quote(ref, safe='')}/json")
        if status == 404:
            return None
        if status != 200:
            raise Unavailable(f"docker inspect {ref}: HTTP {status}")
        return json.loads(payload)

    def read(self, name: str, path: str) -> tuple[str, bytes | str] | None:
        status, payload = self._call("GET", f"/containers/{quote(name, safe='')}/archive?path={quote(path, safe='')}")
        if status == 404:
            return None
        if status != 200:
            raise Unavailable(f"docker archive {name}:{path}: HTTP {status}")
        try:
            with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
                member = tar.next()
                if member is None:
                    return None
                if member.issym():
                    return "link", member.linkname
                if member.isfile():
                    return "file", tar.extractfile(member).read()
                return "other", ""
        except tarfile.TarError as exc:
            raise Unavailable(f"docker archive {name}:{path}: {exc}") from exc

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
        # The stream ends before the daemon records the exit: ask until it has.
        deadline = time.monotonic() + EXIT_CODE_WAIT_S
        while True:
            status, payload = self._call("GET", f"/exec/{exec_id}/json")
            doc = json.loads(payload) if status == 200 else {}
            if not doc.get("Running") and doc.get("ExitCode") is not None:
                return int(doc["ExitCode"]), out, err
            if time.monotonic() > deadline:
                raise Unavailable(f"docker exec {name}: no exit code after {EXIT_CODE_WAIT_S}s")
            time.sleep(0.05)


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

    def _resolve(self, ref: str, allowed: set[str] | list[str], what: str) -> dict | None:
        """The daemon names the container; the list then decides. None: not one we serve."""
        doc = self.docker.container(ref)
        if doc is None or str(doc.get("Name", "")).lstrip("/") not in allowed:
            return None
        return doc

    def _host(self, host: str) -> str:
        doc = self._resolve(host, self.hosts, "host")
        if doc is None:
            raise _fail(404, f"host {host!r} is not enrolled")
        name = str(doc["Name"]).lstrip("/")
        if not doc.get("State", {}).get("Running"):
            raise _fail(503, f"host {name!r} is enrolled but not running")
        return name

    def _file(self, host: str, path: str) -> bytes | None:
        """`path`'s content in the host, symlinks followed inside its filesystem; None if absent."""
        for _ in range(MAX_LINKS + 1):
            found = self.docker.read(host, path)
            if found is None:
                return None
            kind, data = found
            if kind == "file":
                return data
            if kind != "link":
                raise _fail(503, f"{path!r} on {host} is not a regular file")
            path = posixpath.normpath(posixpath.join(posixpath.dirname(path), data))
        raise _fail(503, f"{path!r} on {host}: more than {MAX_LINKS} symlinks")

    def _required(self, host: str, path: str) -> str:
        data = self._file(host, path)
        if data is None:
            raise _fail(503, f"{path} is missing on {host}")
        return data.decode(errors="replace")

    def _passwd(self, host: str) -> list[str]:
        return [line for line in self._required(host, "/etc/passwd").splitlines()
                if line and not line.startswith("#")]

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
                listed = []
                for h in self.hosts:
                    doc = self.docker.container(h)
                    listed.append({"name": h, "running": bool(doc and doc.get("State", {}).get("Running"))})
                return {"hosts": listed}
            case ["hosts", host, "processes"]:
                host = self._host(host)
                code, out, err = self.docker.exec(host, self.ps)
                if code != 0:
                    why = err.decode(errors="replace").strip()[:300] or "no stderr"
                    raise _fail(503, f"{self.ps[0]} on {host} exited {code}: {why}")
                return {"ps_output": out.decode(errors="replace")}
            case ["hosts", host, "accounts"]:
                return {"entries": self._passwd(self._host(host))}
            case ["hosts", host, "accounts", user, "authorized-keys"]:
                return self._authorized_keys(host, user)
            case ["hosts", host, "files", "sha256"]:
                return self._sha256(host, query.get("path", []))
            case ["hosts", host, "packages"]:
                return {"packages": dpkg_packages(self._required(self._host(host), DPKG_STATUS))}
            case ["containers", ref]:
                doc = self._resolve(ref, self.inspectable, "container")
                if doc is None:
                    raise _fail(404, f"no such container: {ref}")
                return {"name": str(doc.get("Name", "")).lstrip("/"),
                        "image": str(doc.get("Config", {}).get("Image", ""))}
        raise _fail(404, "no such route")

    def _authorized_keys(self, host: str, user: str) -> dict:
        if not SAFE_USERNAME_RE.match(user):
            raise _fail(400, f"refusing unsafe user value: {user!r}")
        host = self._host(host)
        record = next((line.split(":") for line in self._passwd(host) if line.split(":", 1)[0] == user), None)
        if record is None:
            raise _fail(404, f"user {user!r} not found on {host}")
        if len(record) < 6 or not record[5].startswith("/"):
            raise _fail(503, f"malformed passwd record for {user!r}")
        path = posixpath.join(record[5], ".ssh/authorized_keys")
        data = self._file(host, path)
        if data is None:
            return {"path": path, "keys": []}
        return {"path": path, "keys": [line for line in data.decode(errors="replace").splitlines()
                                       if line.strip() and not line.startswith("#")]}

    def _sha256(self, host: str, paths: list[str]) -> dict:
        if len(paths) != 1:
            raise _fail(400, "exactly one path is required")
        path = paths[0]
        if not SAFE_PATH_RE.match(path) or any(s in (".", "..") for s in path.split("/")):
            raise _fail(400, f"refusing unsafe path value: {path!r}")
        host = self._host(host)
        data = self._file(host, path)
        if data is None:
            raise _fail(404, f"{path!r} does not exist on {host}")
        return {"sha256": hashlib.sha256(data).hexdigest()}


def dpkg_packages(status: str) -> list[str]:
    """`<package> <version>` per package dpkg knows, as `dpkg-query -W -f='${Package} ${Version}\\n'`
    prints them: every stanza of the status file except a purged (`not-installed`) one."""
    out = []
    for stanza in status.split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if "Package" not in fields or fields.get("Status", "").split()[-1:] == ["not-installed"]:
            continue
        out.append(f"{fields['Package']} {fields.get('Version', '')}")
    return out


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
