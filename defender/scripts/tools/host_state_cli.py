#!/usr/bin/env python3
"""Host live-state CLI — defender-side adapter.

No HTTP. Each verb wraps a single
    `docker --context soc-playground exec <host> <command>`
and renders the relevant output. Outputs are point-in-time; two calls
seconds apart can legitimately disagree on volatile state (process
tables in particular).

Usage:
    host_state_cli.py health-check                       # docker context check
    host_state_cli.py container-inspect <container_id>   # name + image (docker inspect)
    host_state_cli.py proc-tree web-1
    host_state_cli.py passwd web-1
    host_state_cli.py authorized-keys web-1 [--user dev.dana]
    host_state_cli.py fim-checksum web-1 /etc/passwd
    host_state_cli.py package-list web-1

Exit codes:
    0 — success
    1 — verb-level error (file not found, user not present)
    2 — docker / host-unreachable / timeout
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
import sys as _sys
from pathlib import Path as _Path
if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.tools import _stub_transport as transport

SYSTEM = "host-state"
# Hosts addressable via the soc-playground docker context. The list is
# advisory — we don't validate, just surface a hint when the user
# misspells one. Source of truth is `docker context ps`; this list
# tracks playground-v2/hosts/inventory.yaml.
KNOWN_HOSTS = (
    "web-1", "web-2", "db-1", "jump-box-1",
    "dev-ws-1", "office-ws-1", "office-ws-2", "canary-1",
)
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./@:+-]+$")
DEFAULT_TIMEOUT_SEC = 15


def _check_host(host: str):
    if host not in KNOWN_HOSTS:
        print(
            f"warning: host {host!r} is not in the known inventory "
            f"({', '.join(KNOWN_HOSTS)}); attempting anyway.",
            file=sys.stderr,
        )


def _exec(host: str, argv: list[str], *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> tuple[int, str, str]:
    return transport.docker_exec_raw(host, argv, timeout_sec=timeout_sec)


def _exit_on_docker_error(rc: int, stderr: str, host: str):
    """Map docker-exec stderr patterns to clean exits.

    Transport/unreachable failures exit 2 (the system-of-record contract: 2 =
    connectivity/docker/unreachable, matching this CLI's SKILL and the gather
    exit-code protocol) so the circuit breaker counts them. They are identified by
    docker's own connection/lookup signatures, because docker is *loud* about them
    (container missing, daemon/context unreachable). Everything else — including a
    quiet non-zero inner command with empty stderr — is a verb-level error (exit 1)
    the caller reasons about, not a down host: a quiet command failure has empty
    stderr precisely because docker exec itself succeeded, and scoring it as infra
    would spuriously trip the breaker on a perfectly reachable host.
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
        print(
            f"error: host {host!r} unreachable: {s}\n"
            f"hint: `docker --context {transport.DOCKER_CONTEXT} ps` lists running hosts.",
            file=sys.stderr,
        )
        sys.exit(2)
    print(f"error: docker exec on {host} (rc={rc}): {s or 'no stderr'}", file=sys.stderr)
    sys.exit(1)


def cmd_health_check(args, _config):
    """Lightweight: verify the docker context can list containers."""
    cmd = ["docker", "--context", transport.DOCKER_CONTEXT, "ps", "--format", "{{.Names}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        print("error: docker CLI not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(f"error: `docker --context {transport.DOCKER_CONTEXT} ps` timed out after 10s", file=sys.stderr)
        sys.exit(2)
    if proc.returncode != 0:
        print(
            f"error: docker context {transport.DOCKER_CONTEXT!r} unreachable: "
            f"{proc.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(2)
    names = set(proc.stdout.split())
    print("connected")
    print(f"docker context: {transport.DOCKER_CONTEXT}")
    present = sorted(n for n in KNOWN_HOSTS if n in names)
    missing = sorted(n for n in KNOWN_HOSTS if n not in names)
    print(f"hosts present ({len(present)}/{len(KNOWN_HOSTS)}): {', '.join(present) or '—'}")
    if missing:
        print(f"hosts missing: {', '.join(missing)}")


def cmd_container_inspect(args, _config):
    """Container name + image by container id — daemon-level `docker inspect`.

    Unlike the other verbs this takes a container id, not a known host name
    (Falco alerts carry the runtime container id), so it neither runs
    _check_host nor routes through docker exec. Docker resolves partial-hash
    ids without a separate lookup.
    """
    fmt = "{{json .Name}}\t{{json .Config.Image}}"
    rc, out, err = transport.docker_inspect_raw(args.container_id, fmt=fmt)
    if rc != 0:
        s = err.strip()
        if "No such object" in s or "No such container" in s:
            sys.exit(
                f"error: no container matching {args.container_id!r} on "
                f"context {transport.DOCKER_CONTEXT!r}: {s}"
            )
        sys.exit(f"error: docker inspect failed (rc={rc}): {s}")
    parts = out.strip().split("\t")
    # `.Name` comes back with a leading slash (docker's canonical form).
    name = json.loads(parts[0]).lstrip("/") if parts and parts[0] else ""
    image = json.loads(parts[1]) if len(parts) > 1 and parts[1] else ""
    if args.raw:
        print(json.dumps({
            "container_id": args.container_id,
            "captured_at": _utcnow_z(),
            "name": name,
            "image": image,
        }))
        return
    print(f"container_id: {args.container_id}")
    print(f"captured_at: {_utcnow_z()}")
    print(f"name: {name}")
    print(f"image: {image}")


def cmd_proc_tree(args, _config):
    _check_host(args.host)
    rc, out, err = _exec(args.host, ["ps", "-eo", "pid,ppid,user,stat,etime,cmd", "--forest"])
    _exit_on_docker_error(rc, err, args.host)
    if args.raw:
        print(json.dumps({"host": args.host, "captured_at": _utcnow_z(), "ps_output": out}))
        return
    print(f"host: {args.host}")
    print(f"captured_at: {_utcnow_z()}")
    print(out)


def cmd_passwd(args, _config):
    _check_host(args.host)
    rc, out, err = _exec(args.host, ["cat", "/etc/passwd"])
    _exit_on_docker_error(rc, err, args.host)
    entries = [line for line in out.splitlines() if line and not line.startswith("#")]
    if args.raw:
        print(json.dumps({
            "host": args.host,
            "captured_at": _utcnow_z(),
            "entries": entries,
        }))
        return
    print(f"host: {args.host}")
    print(f"captured_at: {_utcnow_z()}")
    print(f"entries: {len(entries)}")
    for e in entries:
        print(e)


def cmd_authorized_keys(args, _config):
    _check_host(args.host)
    user = args.user or "root"
    if not SAFE_USERNAME_RE.match(user):
        sys.exit(f"error: refusing unsafe --user value: {user!r}")
    # Use getent so we get the right home dir for system + UNIX-PAM users.
    rc, home_out, err = _exec(args.host, ["getent", "passwd", user])
    if rc != 0 or not home_out.strip():
        sys.exit(f"error: user {user!r} not found on {args.host}")
    parts = home_out.strip().split(":")
    if len(parts) < 6:
        sys.exit(f"error: malformed passwd record for {user!r}: {home_out!r}")
    home = parts[5]
    ak_path = f"{home}/.ssh/authorized_keys"
    rc, out, err = _exec(args.host, ["cat", ak_path])
    if rc != 0:
        s = err.strip()
        # Treat missing file as "no keys" rather than an error — common
        # for unprivileged users on a freshly-seeded host.
        if "No such file" in s:
            keys: list[str] = []
        else:
            _exit_on_docker_error(rc, err, args.host)
            keys = []  # unreachable, _exit_on_docker_error sys.exits
    else:
        keys = [line for line in out.splitlines() if line.strip() and not line.startswith("#")]

    if args.raw:
        print(json.dumps({
            "host": args.host,
            "user": user,
            "path": ak_path,
            "captured_at": _utcnow_z(),
            "keys": keys,
        }))
        return
    print(f"host: {args.host}")
    print(f"user: {user}")
    print(f"path: {ak_path}")
    print(f"captured_at: {_utcnow_z()}")
    print(f"key count: {len(keys)}")
    for k in keys:
        # Fingerprint summary: type + last-32-chars + comment
        head = k.split()
        if len(head) >= 2:
            ktype = head[0]
            tail = head[1][-32:]
            comment = " ".join(head[2:]) if len(head) > 2 else ""
            print(f"- {ktype} …{tail} {comment}".rstrip())
        else:
            print(f"- {k[:80]}…")


def cmd_fim_checksum(args, _config):
    _check_host(args.host)
    if not SAFE_PATH_RE.match(args.path) or not args.path.startswith("/"):
        sys.exit(f"error: refusing unsafe --path value: {args.path!r}")
    rc, out, err = _exec(args.host, ["sha256sum", args.path])
    if rc != 0:
        s = err.strip()
        if "No such file" in s:
            sys.exit(f"error: {args.path!r} does not exist on {args.host}")
        _exit_on_docker_error(rc, err, args.host)
    digest = out.split()[0] if out.strip() else ""
    if args.raw:
        print(json.dumps({
            "host": args.host,
            "path": args.path,
            "captured_at": _utcnow_z(),
            "sha256": digest,
        }))
        return
    print(f"host: {args.host}")
    print(f"path: {args.path}")
    print(f"captured_at: {_utcnow_z()}")
    print(f"sha256: {digest}")


def cmd_package_list(args, _config):
    _check_host(args.host)
    # dpkg-query is present on every host (ubuntu base in playground-v2).
    fmt = r"${Package} ${Version}\n"
    rc, out, err = _exec(args.host, ["dpkg-query", "-W", "-f=" + fmt], timeout_sec=30)
    _exit_on_docker_error(rc, err, args.host)
    pkgs = [line for line in out.splitlines() if line.strip()]
    if args.raw:
        print(json.dumps({
            "host": args.host,
            "captured_at": _utcnow_z(),
            "packages": pkgs,
        }))
        return
    print(f"host: {args.host}")
    print(f"captured_at: {_utcnow_z()}")
    print(f"package count: {len(pkgs)}")
    for p in pkgs[: args.limit]:
        print(p)
    if len(pkgs) > args.limit:
        print(f"… ({len(pkgs) - args.limit} more — use --raw for full list)")


def _utcnow_z() -> str:
    import datetime
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_parser():
    p = transport.AdapterArgumentParser(
        description="Host live-state CLI — per-host point-in-time observations via docker exec.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="Verify docker context + list known hosts.")

    ci = sub.add_parser(
        "container-inspect",
        help="Container name + image by container id (docker inspect).",
    )
    ci.add_argument("container_id")
    ci.add_argument("--raw", action="store_true")

    pt = sub.add_parser("proc-tree", help="Process forest (ps -eo ... --forest).")
    pt.add_argument("host")
    pt.add_argument("--raw", action="store_true")

    pw = sub.add_parser("passwd", help="/etc/passwd contents.")
    pw.add_argument("host")
    pw.add_argument("--raw", action="store_true")

    ak = sub.add_parser("authorized-keys", help="<user>'s ~/.ssh/authorized_keys.")
    ak.add_argument("host")
    ak.add_argument("--user", help="Default: root.")
    ak.add_argument("--raw", action="store_true")

    fim = sub.add_parser("fim-checksum", help="SHA-256 of a single file.")
    fim.add_argument("host")
    fim.add_argument("path", help="Absolute path on <host>.")
    fim.add_argument("--raw", action="store_true")

    pl = sub.add_parser("package-list", help="Installed dpkg packages.")
    pl.add_argument("host")
    pl.add_argument(
        "--limit", type=int, default=200,
        help="Cap rows shown in text mode (default 200). Raw mode is uncapped.",
    )
    pl.add_argument("--raw", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    # host-state has no URL/bastion; the shared config schema (URL_BASE +
    # BASTION_HOST + TIMEOUT_SEC) doesn't apply. The default timeout lives
    # in this module; nothing else is configurable today.
    config: dict[str, str] = {"TIMEOUT_SEC": str(DEFAULT_TIMEOUT_SEC)}

    if args.subcommand == "health-check":
        cmd_health_check(args, config)
    elif args.subcommand == "container-inspect":
        cmd_container_inspect(args, config)
    elif args.subcommand == "proc-tree":
        cmd_proc_tree(args, config)
    elif args.subcommand == "passwd":
        cmd_passwd(args, config)
    elif args.subcommand == "authorized-keys":
        cmd_authorized_keys(args, config)
    elif args.subcommand == "fim-checksum":
        cmd_fim_checksum(args, config)
    elif args.subcommand == "package-list":
        cmd_package_list(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
