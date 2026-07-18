"""Host live-state adapter — the `host-state` VERBS registry.

No HTTP. Each verb wraps a single
    `docker --context <the run's context> exec <host> <command>`
and renders the relevant output. Outputs are point-in-time; two calls
seconds apart can legitimately disagree on volatile state (process
tables in particular).

Verbs (`VERBS` is the whole model-facing surface — there is no CLI):
    health-check
    container-inspect  container_id
    proc-tree          host
    passwd             host
    authorized-keys    host [user]
    fim-checksum       host, path
    package-list       host

`fim-checksum`'s `path` is the ONE declared exception to "no verb names a path": it is a
path on a playground TARGET host, reached through `docker exec` — never a path in the
driver's namespace. It stays behind SAFE_PATH_RE + the absolute-path check.

Faults (`faults.py`): TransportFault = the host/docker is down (2), UpstreamFault = the
verb's own answer says no (1) — a missing file, an unknown user, an unsafe argument.
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (see cmdb_adapter.py).
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import TransportFault, UpstreamFault

SYSTEM = "host-state"
# Hosts addressable via the soc-playground docker context. The list is
# advisory — we don't validate, just surface a hint when the caller
# misspells one. Source of truth is `docker context ps`; this list
# tracks playground-v2/hosts/inventory.yaml.
KNOWN_HOSTS = (
    "web-1", "web-2", "db-1", "jump-box-1",
    "dev-ws-1", "office-ws-1", "office-ws-2", "canary-1",
)
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./@:+-]+$")
DEFAULT_TIMEOUT_SEC = 15
HEALTH_TIMEOUT_SEC = 10


def _check_host(host: str) -> None:
    if host not in KNOWN_HOSTS:
        print(
            f"warning: host {host!r} is not in the known inventory "
            f"({', '.join(KNOWN_HOSTS)}); attempting anyway.",
            file=sys.stderr,
        )


def _exec(
    ctx: VerbContext, host: str, argv: list[str], *, timeout_sec: int = DEFAULT_TIMEOUT_SEC
) -> tuple[int, str, str]:
    return transport.docker_exec_raw(ctx, host, argv, timeout_sec=timeout_sec)


def _raise_on_docker_error(ctx: VerbContext, rc: int, stderr: str, host: str) -> None:
    """Map docker-exec stderr patterns onto the fault taxonomy.

    Transport/unreachable failures are `TransportFault` (infra, exit 2) so the circuit
    breaker counts them. They are identified by docker's own connection/lookup signatures,
    because docker is *loud* about them (container missing, daemon/context unreachable).
    Everything else — including a quiet non-zero inner command with empty stderr — is a verb
    -level error the caller reasons about (`UpstreamFault`, exit 1), not a down host: a quiet
    command failure has empty stderr precisely because docker exec itself succeeded, and
    scoring it as infra would spuriously trip the breaker on a perfectly reachable host.
    """
    if rc == 0:
        return
    s = stderr.strip()
    transport_down = (
        "No such container" in s or "is not running" in s
        or "Cannot connect to the Docker daemon" in s
        or "error during connect" in s
    )
    if transport_down:
        raise TransportFault(
            f"host {host!r} unreachable: {s} — "
            f"`docker --context {transport.docker_context(ctx)} ps` lists running hosts."
        )
    raise UpstreamFault(f"docker exec on {host} (rc={rc}): {s or 'no stderr'}")


def _utcnow_z() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def health_check(ctx: VerbContext) -> dict:
    """Lightweight: verify the docker context can list containers. RETURNS the roster —
    the prose this used to print has no answer under "a verb returns its payload", and the
    queries row would carry an empty payload for the one call whose whole point is to say
    whether the system is up."""
    context = transport.docker_context(ctx)
    cmd = ["docker", "--context", context, "ps", "--format", "{{.Names}}"]
    try:
        # LOSSY decode + a MANDATORY timeout, like every other transport in the family:
        # container names are foreign bytes, and a strict decode raises UnicodeDecodeError —
        # a ValueError, which sails past every guard below.
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
    """Container name + image by container id — daemon-level `docker inspect`.

    Unlike the other verbs this takes a container id, not a known host name
    (Falco alerts carry the runtime container id), so it neither runs
    _check_host nor routes through docker exec. Docker resolves partial-hash
    ids without a separate lookup.
    """
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
    # `.Name` comes back with a leading slash (docker's canonical form).
    name = json.loads(parts[0]).lstrip("/") if parts and parts[0] else ""
    image = json.loads(parts[1]) if len(parts) > 1 and parts[1] else ""
    return {
        "container_id": container_id,
        "captured_at": _utcnow_z(),
        "name": name,
        "image": image,
    }


def proc_tree(ctx: VerbContext, *, host: str) -> dict:
    _check_host(host)
    rc, out, err = _exec(ctx, host, ["ps", "-eo", "pid,ppid,user,stat,etime,cmd", "--forest"])
    _raise_on_docker_error(ctx, rc, err, host)
    return {"host": host, "captured_at": _utcnow_z(), "ps_output": out}


def passwd(ctx: VerbContext, *, host: str) -> dict:
    _check_host(host)
    rc, out, err = _exec(ctx, host, ["cat", "/etc/passwd"])
    _raise_on_docker_error(ctx, rc, err, host)
    entries = [line for line in out.splitlines() if line and not line.startswith("#")]
    return {"host": host, "captured_at": _utcnow_z(), "entries": entries}


def authorized_keys(ctx: VerbContext, *, host: str, user: str = "root") -> dict:
    _check_host(host)
    if not SAFE_USERNAME_RE.match(user):
        raise UpstreamFault(f"refusing unsafe user value: {user!r}")
    # Use getent so we get the right home dir for system + UNIX-PAM users.
    rc, home_out, err = _exec(ctx, host, ["getent", "passwd", user])
    if rc != 0 or not home_out.strip():
        raise UpstreamFault(f"user {user!r} not found on {host}")
    parts = home_out.strip().split(":")
    if len(parts) < 6:
        raise UpstreamFault(f"malformed passwd record for {user!r}: {home_out!r}")
    home = parts[5]
    ak_path = f"{home}/.ssh/authorized_keys"
    rc, out, err = _exec(ctx, host, ["cat", ak_path])
    if rc != 0:
        s = err.strip()
        # Treat missing file as "no keys" rather than an error — common
        # for unprivileged users on a freshly-seeded host.
        if "No such file" not in s:
            _raise_on_docker_error(ctx, rc, err, host)
        keys: list[str] = []
    else:
        keys = [line for line in out.splitlines() if line.strip() and not line.startswith("#")]

    return {
        "host": host,
        "user": user,
        "path": ak_path,
        "captured_at": _utcnow_z(),
        "keys": keys,
    }


def fim_checksum(ctx: VerbContext, *, host: str, path: str) -> dict:
    """SHA-256 of one file ON THE TARGET HOST. `path` is the declared exception to the
    no-path rule: it is resolved inside the playground container by `sha256sum`, never in
    the driver's namespace, and it must be absolute and match SAFE_PATH_RE."""
    _check_host(host)
    if not SAFE_PATH_RE.match(path) or not path.startswith("/"):
        raise UpstreamFault(f"refusing unsafe path value: {path!r}")
    rc, out, err = _exec(ctx, host, ["sha256sum", path])
    if rc != 0:
        s = err.strip()
        if "No such file" in s:
            raise UpstreamFault(f"{path!r} does not exist on {host}")
        _raise_on_docker_error(ctx, rc, err, host)
    digest = out.split()[0] if out.strip() else ""
    return {"host": host, "path": path, "captured_at": _utcnow_z(), "sha256": digest}


def package_list(ctx: VerbContext, *, host: str) -> dict:
    _check_host(host)
    # dpkg-query is present on every host (ubuntu base in playground-v2).
    fmt = r"${Package} ${Version}\n"
    rc, out, err = _exec(ctx, host, ["dpkg-query", "-W", "-f=" + fmt], timeout_sec=30)
    _raise_on_docker_error(ctx, rc, err, host)
    pkgs = [line for line in out.splitlines() if line.strip()]
    return {"host": host, "captured_at": _utcnow_z(), "packages": pkgs}


VERBS = {
    "health-check": health_check,
    "container-inspect": container_inspect,
    "proc-tree": proc_tree,
    "passwd": passwd,
    "authorized-keys": authorized_keys,
    "fim-checksum": fim_checksum,
    "package-list": package_list,
}
