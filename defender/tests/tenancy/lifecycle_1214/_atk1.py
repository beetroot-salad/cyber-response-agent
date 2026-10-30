"""Machinery for the #1214 round-5 attack-1 cases (lifecycle and recovery) — NO test functions, NO production imports.
Extends `_fakes` without touching it: a transport that echoes credentials, one that raises, a forge that pages,
a `docker` on PATH, a repository whose holds are watched, and a TTL parser."""
from __future__ import annotations

import contextlib
import json
import re
import subprocess
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx

_CREDENTIAL_FIELDS = ("password", "secret_id", "token")


def credentials_of(request: httpx.Request) -> list[str]:
    """Every credential a request carries: the Authorization value after its scheme, X-Vault-Token, and the
    password / secret_id / token fields of a JSON body."""
    found: list[str] = []
    auth = request.headers.get("authorization")
    if auth:
        found.append(auth.split(" ", 1)[-1])
    if request.headers.get("x-vault-token"):
        found.append(request.headers["x-vault-token"])
    if request.content:
        with contextlib.suppress(ValueError):
            body = json.loads(request.content)
            if isinstance(body, dict):
                found += [str(body[k]) for k in _CREDENTIAL_FIELDS if body.get(k)]
    return found


class Echo:
    """An `httpx` transport over a fake's `handle` that answers 500 to the first request `when` accepts, with an
    error message that repeats every credential the request carried (a server that echoes what it was sent). With
    `straddle=(step,)` the message is padded so the first credential begins well before the 600-character cut of the
    failure text `"<step>: <method> <path> answered 500: <message>"`."""

    def __init__(self, handle: Callable[[httpx.Request], httpx.Response], when: Callable[[httpx.Request], bool],
                 *, straddle: str | None = None) -> None:
        self.handle, self.when, self.straddle = handle, when, straddle
        self.hit: list[httpx.Request] = []
        self.secrets: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.hit or not self.when(request):
            return self.handle(request)
        self.hit.append(request)
        self.secrets = credentials_of(request)
        message = "rejected credentials: " + " ".join(self.secrets)
        if self.straddle is not None:
            prefix = f"{self.straddle}: {request.method} {request.url.path} answered 500: "
            message = "x" * (575 - len(prefix)) + " ".join(self.secrets)
        return httpx.Response(500, json={"message": message})


class Raises:
    """An `httpx` transport over a fake's `handle` that raises `error` (a transport failure, not an HTTP answer) for the
    first request `when` accepts."""

    def __init__(self, handle: Callable[[httpx.Request], httpx.Response], when: Callable[[httpx.Request], bool],
                 error: BaseException) -> None:
        self.handle, self.when, self.error = handle, when, error
        self.hit: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self.hit and self.when(request):
            self.hit.append(request)
            raise self.error
        return self.handle(request)


class EchoGit:
    """The git runner, except that a push fails (once) with a message repeating the credential's token, as a git
    server echoing the header it refused would."""

    def __init__(self, inner: Any) -> None:
        self.inner, self.tokens = inner, []

    def __call__(self, args: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        if "push" in [str(a) for a in args] and kw.get("identity") is not None and not self.tokens:
            token = kw["identity"].token(min_validity=60.0)
            self.tokens.append(token)
            return subprocess.CompletedProcess(args, 1, "", f"fatal: authentication failed for header {token}")
        return self.inner(args, **kw)


def page_collaborators(forge: Any, *, default_limit: int = 30, max_limit: int = 50) -> None:
    """Make `forge` answer `GET .../collaborators` as Forgejo does: `page` and `limit` honoured (default 30, at most 50),
    a page past the end empty. Replaces `forge.handle`, so it must be called before any client is built from it."""
    inner = forge.handle

    def handle(request: httpx.Request) -> httpx.Response:
        answer = inner(request)
        parts = request.url.path.split("/")
        if request.method != "GET" or parts[-1] != "collaborators" or answer.status_code != 200:
            return answer
        page = int(request.url.params.get("page", 1))
        limit = min(int(request.url.params.get("limit", default_limit)), max_limit)
        everyone = answer.json()
        return httpx.Response(200, json=everyone[(page - 1) * limit: page * limit])
    forge.handle = handle


_DOCKER = textwrap.dedent('''\
    #!PYTHON
    import json, pathlib, sys
    state = pathlib.Path("STATE")
    data = json.loads(state.read_text())
    args = sys.argv[1:]
    data["calls"].append(args)
    out = ""
    if args[:1] == ["ps"]:
        wanted = args[args.index("--filter") + 1].removeprefix("label=")
        key, sep, value = wanted.partition("=")
        out = "\\n".join(c for c, labels in data["containers"].items()
                        if key in labels and (not sep or labels[key] == value))
    elif args[:1] == ["wait"]:
        data["waited"] += args[1:]
    elif args[:1] == ["rm"]:
        ids = [a for a in args[1:] if not a.startswith("-")]
        stuck = [i for i in ids if data["containers"].get(i, {}).get("paused") and i not in data["waited"]]
        if stuck:
            state.write_text(json.dumps(data))
            sys.stderr.write("PID is zombie and can not be killed\\n")
            sys.exit(1)
        data["removed"] += ids
        for i in ids:
            data["containers"].pop(i, None)
    state.write_text(json.dumps(data))
    print(out)
    ''')


class DockerShim:
    """A `docker` executable in `root`: `ps -aq --filter label=K[=V]` lists the containers (id -> labels) carrying the
    label, `rm -f ids` removes them; a container labelled `paused` refuses `rm` until it was `wait`ed for (gVisor's
paused box, #1202). Every call is recorded. Put `root` first on PATH."""

    def __init__(self, root: Path, containers: dict[str, dict[str, str]]) -> None:
        root.mkdir(parents=True)
        self.root, self.state = root, root / "state.json"
        self.state.write_text(json.dumps({"containers": containers, "calls": [], "removed": [], "waited": []}))
        script = root / "docker"
        script.write_text(_DOCKER.replace("PYTHON", sys.executable).replace("STATE", str(self.state)))
        script.chmod(0o755)

    def _read(self) -> dict[str, Any]:
        return json.loads(self.state.read_text())

    def calls(self) -> list[list[str]]:
        return self._read()["calls"]

    def removed(self) -> list[str]:
        return self._read()["removed"]

    def remaining(self) -> set[str]:
        return set(self._read()["containers"])


class _Watched:
    """A hold whose `commit` is reported to the watcher first; everything else is the real hold's."""

    def __init__(self, held: Any, log: list[tuple[Any, Any]], before: Callable[[Any, dict[str, Any]], None] | None) -> None:
        self._held, self._log, self._before = held, log, before

    def __getattr__(self, name: str) -> Any:
        return getattr(self._held, name)

    async def commit(self, **kwargs: Any) -> Any:
        record = self._held.record
        self._log.append((record.pending_action, record.step))
        if self._before is not None:
            self._before(record, kwargs)
        return await self._held.commit(**kwargs)


def watch_commits(tenants: Any, *, before: Callable[[Any, dict[str, Any]], None] | None = None) -> list[tuple[Any, Any]]:
    """Make every hold `tenants.lock` yields report each commit as (pending action, step) BEFORE it is made, in order;
    `before(record, kwargs)` runs first and may raise (e.g. `FenceMissed`). The list is returned live."""
    log: list[tuple[Any, Any]] = []
    real = tenants.lock

    @contextlib.asynccontextmanager
    async def lock(tenant_id: str) -> AsyncIterator[Any]:
        async with real(tenant_id) as held:
            yield None if held is None else _Watched(held, log, before)
    tenants.lock = lock
    return log


_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600}


def seconds(ttl: Any) -> int:
    """A TTL as OpenBao takes it (a number of seconds, or `10m` / `600s` / `1h`), in seconds."""
    found = re.fullmatch(r"(\d+)([smh]?)", str(ttl).strip())
    assert found, f"not a TTL: {ttl!r}"
    return int(found.group(1)) * _UNITS[found.group(2)]
