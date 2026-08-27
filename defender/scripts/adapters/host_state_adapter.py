
from __future__ import annotations

import datetime
import json
import re
import subprocess

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender import _clock
from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.confinement import confine_host_state_call
from defender.scripts.adapters.faults import TransportFault, UpstreamFault

SYSTEM = "host-state"
KNOWN_HOSTS = (
    "web-1", "web-2", "db-1", "jump-box-1",
    "dev-ws-1", "office-ws-1", "office-ws-2", "canary-1",
)
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./@:+-]+$")
DEFAULT_TIMEOUT_SEC = 15
HEALTH_TIMEOUT_SEC = 10


def _exec(
    ctx: VerbContext, host: str, argv: list[str], *, timeout_sec: int = DEFAULT_TIMEOUT_SEC
) -> tuple[int, str, str]:
    return transport.docker_exec_raw(ctx, host, argv, timeout_sec=timeout_sec)


def _raise_on_docker_error(ctx: VerbContext, rc: int, stderr: str, host: str) -> None:
    if rc == 0:
        return
    s = stderr.strip()
    transport_down = (
        "No such container" in s or "is not running" in s
        or "Cannot connect to the Docker daemon" in s
        or "error during connect" in s
        or "context not found" in s
        or "unable to resolve docker endpoint" in s
    )
    if transport_down:
        raise TransportFault(
            f"host {host!r} unreachable: {s} — "
            f"`docker --context {transport.docker_context(ctx)} ps` lists running hosts."
        )
    raise UpstreamFault(f"docker exec on {host} (rc={rc}): {s or 'no stderr'}")


def _captured_at(ctx: VerbContext) -> str:
    """When this observation was taken, as the RUN reckons time.

    This adapter is the only one of the seven that mints a timestamp, and `captured_at` is the
    one field in a served payload that is not a function of the question asked. On an ordinary
    run that is exactly right — a host-state read IS a point-in-time capture, and the skill
    tells its readers to cross-reference the value against event timestamps. On a BRANCHED run
    it is what makes an episode unreplayable: two siblings forked from one branch point, or one
    episode re-run a week later, produce different bytes for identical questions, and the
    difference belongs to neither world. `ctx.as_of` is the branch point's moment, so the
    stamp describes the world the sibling is living in rather than the afternoon it executed.

    `getattr` rather than `ctx.as_of`, for the reason `elastic_adapter` reads `world_id` the
    same way: this adapter is reached with duck-typed contexts from the CLI lane and from test
    stubs, and an `AttributeError` inside a verb body is not an `AdapterFault` — the query tool
    files it as exit 2, an INFRA code, so a shape mismatch would read as the estate being down.

    THE ONE ANCHOR for the optionality: resolved here, once, and every caller below takes a
    concrete string. `health_check` is deliberately not a caller — it stamps nothing today,
    reaches no corpus, and a liveness probe that grew a timestamp would be a contract change
    for no gain.
    """
    at = getattr(ctx, "as_of", None)
    return _clock.z_seconds(datetime.datetime.now(datetime.UTC) if at is None else at)


def health_check(ctx: VerbContext) -> dict:
    context = transport.docker_context(ctx)
    cmd = ["docker", "--context", context, "ps", "--format", "{{.Names}}"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=HEALTH_TIMEOUT_SEC,
            encoding="utf-8", errors="replace", env=dict(ctx.env),
        )
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"`docker --context {context} ps` timed out after {HEALTH_TIMEOUT_SEC}s"
        ) from e
    if proc.returncode != 0:
        raise TransportFault(
            f"docker context {context!r} unreachable: {proc.stderr.strip()}"
        )
    names = set(proc.stdout.split())
    return {
        "system": SYSTEM,
        "connected": True,
        "docker_context": context,
        "hosts_present": sorted(n for n in KNOWN_HOSTS if n in names),
        "hosts_missing": sorted(n for n in KNOWN_HOSTS if n not in names),
    }


def container_inspect(ctx: VerbContext, *, container_id: str) -> dict:
    fmt = "{{json .Name}}\t{{json .Config.Image}}"
    rc, out, err = transport.docker_inspect_raw(ctx, container_id, fmt=fmt)
    if rc != 0:
        s = err.strip()
        if "No such object" in s or "No such container" in s:
            raise UpstreamFault(
                f"no container matching {container_id!r} on "
                f"context {transport.docker_context(ctx)!r}: {s}"
            )
        raise TransportFault(f"docker inspect failed (rc={rc}): {s}")
    parts = out.strip().split("\t")
    name = json.loads(parts[0]).lstrip("/") if parts and parts[0] else ""
    image = json.loads(parts[1]) if len(parts) > 1 and parts[1] else ""
    return {
        "container_id": container_id,
        "captured_at": _captured_at(ctx),
        "name": name,
        "image": image,
    }


def proc_tree(ctx: VerbContext, *, host: str) -> dict:
    confine_host_state_call("ps", host)
    rc, out, err = _exec(ctx, host, ["ps", "-eo", "pid,ppid,user,stat,etime,cmd", "--forest"])
    _raise_on_docker_error(ctx, rc, err, host)
    return {"host": host, "captured_at": _captured_at(ctx), "ps_output": out}


def passwd(ctx: VerbContext, *, host: str) -> dict:
    confine_host_state_call("cat", host)
    rc, out, err = _exec(ctx, host, ["cat", "/etc/passwd"])
    _raise_on_docker_error(ctx, rc, err, host)
    entries = [line for line in out.splitlines() if line and not line.startswith("#")]
    return {"host": host, "captured_at": _captured_at(ctx), "entries": entries}


def authorized_keys(ctx: VerbContext, *, host: str, user: str = "root") -> dict:
    confine_host_state_call("getent", host)
    if not SAFE_USERNAME_RE.match(user):
        raise UpstreamFault(f"refusing unsafe user value: {user!r}")
    rc, home_out, err = _exec(ctx, host, ["getent", "passwd", user])
    if rc != 0 or not home_out.strip():
        raise UpstreamFault(f"user {user!r} not found on {host}")
    parts = home_out.strip().split(":")
    if len(parts) < 6:
        raise UpstreamFault(f"malformed passwd record for {user!r}: {home_out!r}")
    home = parts[5]
    ak_path = f"{home}/.ssh/authorized_keys"
    confine_host_state_call("cat", host)
    rc, out, err = _exec(ctx, host, ["cat", ak_path])
    if rc != 0:
        s = err.strip()
        if "No such file" not in s:
            _raise_on_docker_error(ctx, rc, err, host)
        keys: list[str] = []
    else:
        keys = [line for line in out.splitlines() if line.strip() and not line.startswith("#")]

    return {
        "host": host,
        "user": user,
        "path": ak_path,
        "captured_at": _captured_at(ctx),
        "keys": keys,
    }


def fim_checksum(ctx: VerbContext, *, host: str, path: str) -> dict:
    confine_host_state_call("sha256sum", host)
    if not SAFE_PATH_RE.match(path) or not path.startswith("/"):
        raise UpstreamFault(f"refusing unsafe path value: {path!r}")
    rc, out, err = _exec(ctx, host, ["sha256sum", path])
    if rc != 0:
        s = err.strip()
        if "No such file" in s:
            raise UpstreamFault(f"{path!r} does not exist on {host}")
        _raise_on_docker_error(ctx, rc, err, host)
    digest = out.split()[0] if out.strip() else ""
    return {"host": host, "path": path, "captured_at": _captured_at(ctx), "sha256": digest}


def package_list(ctx: VerbContext, *, host: str) -> dict:
    confine_host_state_call("dpkg-query", host)
    fmt = r"${Package} ${Version}\n"
    rc, out, err = _exec(ctx, host, ["dpkg-query", "-W", "-f=" + fmt], timeout_sec=30)
    _raise_on_docker_error(ctx, rc, err, host)
    pkgs = [line for line in out.splitlines() if line.strip()]
    return {"host": host, "captured_at": _captured_at(ctx), "packages": pkgs}


VERBS = {
    "health-check": health_check,
    "container-inspect": container_inspect,
    "proc-tree": proc_tree,
    "passwd": passwd,
    "authorized-keys": authorized_keys,
    "fim-checksum": fim_checksum,
    "package-list": package_list,
}
