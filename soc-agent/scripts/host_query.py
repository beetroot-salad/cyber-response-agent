#!/usr/bin/env python3
"""Constrained host query CLI for the playground inspection-eligible containers.

A tightly-scoped read-only state interface — equivalent to what an EDR or
osquery installation would expose in a production environment. Internally
uses `docker exec` against one of the whitelisted playground containers,
but the agent never sees raw shell access; only the specific subcommands
defined here.

Subcommands answer "what is currently true on the host" without handing
the agent the answer to the investigation:

  process-list <pattern>     names of running processes matching pattern
  listening-sockets          tcp/udp ports currently listening
  file-stat <path>           metadata only — exists, mtime, mode, owner, size
  package-installed <name>   debian package presence check
  service-status <name>      systemd/init service active/inactive/missing
  connection-list            currently established TCP connections

Select the host via the top-level `--host` flag:

  --host target-endpoint   (default) the alerting workload — primary
                           inspection surface for any alert's dst side
  --host monitoring-host   the playground's monitoring source — used
                           as grounding evidence for the monitoring-probe
                           archetype when the srcip points at this host

Hardened against playground "answer-key" reads:
  - file-stat refuses any path under /opt/workloads/ or /etc/cron.d/
  - No subcommand exposes file CONTENTS — only metadata
  - No shell, pipe, or redirect — each subcommand runs a fixed argv list

Exit codes:
  0 — subcommand succeeded; result printed to stdout
  1 — subcommand failed (invalid args, container error, missing tool)
  2 — request denied (path is in the deny-list, or host not whitelisted)
"""

import argparse
import re
import subprocess
import sys
from pathlib import PurePosixPath

# Hosts the CLI is allowed to docker exec against. Adding a host here is
# a deliberate act — it must be a playground container whose inspection
# surface has a documented SKILL.md under knowledge/environment/systems/.
ALLOWED_HOSTS = ("target-endpoint", "monitoring-host")
DEFAULT_HOST = "target-endpoint"
DOCKER_TIMEOUT_SECONDS = 10

# Paths the agent must not be able to introspect — these are the playground's
# simulation source files. Reading them would short-circuit the investigation
# rather than test the agent's reasoning. In a production environment the
# equivalent would be data-classification regions (secret stores, customer
# data) that the EDR query layer must not surface.
ANSWER_KEY_PREFIXES = (
    "/opt/workloads",
    "/etc/cron.d",
)


def docker_exec(host: str, argv: list[str]) -> tuple[str, int]:
    """Run `docker exec <host> <argv>` and return (output, returncode).

    No shell. argv is passed verbatim to docker as separate args.
    `host` must already have been validated against ALLOWED_HOSTS.
    """
    cmd = ["docker", "exec", host, *argv]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {DOCKER_TIMEOUT_SECONDS}s", 1
    except FileNotFoundError:
        return "error: docker not found on PATH", 1
    if result.returncode != 0:
        err = result.stderr.strip()
        msg = f"error (rc={result.returncode}): {err}" if err else f"error (rc={result.returncode})"
        return msg, 1
    return result.stdout.strip(), 0


def is_answer_key_path(path: str) -> bool:
    """Return True if `path` lies under any deny-list prefix.

    Normalizes `..` and `.` segments before the prefix check so traversal
    attempts cannot bypass the deny-list. Does not resolve symlinks (this
    runs on the host, not inside the container, so it cannot follow them).
    """
    norm = str(PurePosixPath(path))
    for prefix in ANSWER_KEY_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_process_list(args: argparse.Namespace) -> int:
    """List running process names matching a pattern (names only, no argv)."""
    out, rc = docker_exec(args.host, ["ps", "-e", "-o", "comm"])
    if rc != 0:
        print(out, file=sys.stderr)
        return 1
    pattern_re = re.compile(re.escape(args.pattern))
    matches = [
        line.strip() for line in out.splitlines()[1:]  # skip COMMAND header
        if pattern_re.search(line)
    ]
    if not matches:
        print("(no matching processes)")
    else:
        for m in matches:
            print(m)
    return 0


def cmd_listening_sockets(args: argparse.Namespace) -> int:
    """List currently listening TCP and UDP sockets (no process attribution)."""
    out, rc = docker_exec(args.host, ["ss", "-lntu"])
    if rc != 0:
        print(out, file=sys.stderr)
        return 1
    print(out)
    return 0


def cmd_file_stat(args: argparse.Namespace) -> int:
    """Stat a file (metadata only — never contents)."""
    if is_answer_key_path(args.path):
        print(
            f"denied: path '{args.path}' is in the playground answer-key region "
            f"({', '.join(ANSWER_KEY_PREFIXES)}). file-stat does not expose paths "
            f"that would short-circuit the investigation. Use SIEM telemetry "
            f"instead.",
            file=sys.stderr,
        )
        return 2
    out, rc = docker_exec(args.host, [
        "stat", "-c", "%n size=%s mtime=%y mode=%a owner=%U type=%F", args.path,
    ])
    if rc != 0:
        # stat returns non-zero when the file doesn't exist; surface that as
        # a clean negative rather than a tool error.
        print(f"not found: {args.path}")
        return 0
    print(out)
    return 0


def cmd_package_installed(args: argparse.Namespace) -> int:
    """Check if a debian package is installed on the host."""
    out, rc = docker_exec(args.host, ["dpkg-query", "-W", "-f", "${Status}", args.name])
    if rc != 0:
        print(f"{args.name}: not installed")
        return 0
    if "install ok installed" in out:
        print(f"{args.name}: installed")
    else:
        print(f"{args.name}: {out}")
    return 0


def cmd_service_status(args: argparse.Namespace) -> int:
    """Check service status (systemd or sysv init)."""
    out, rc = docker_exec(args.host, ["systemctl", "is-active", args.name])
    if rc == 0:
        print(f"{args.name}: {out.strip()}")
        return 0
    # systemctl returns rc=3 for inactive/failed but writes the state to stdout
    if out and out.strip() in ("inactive", "failed", "activating", "deactivating"):
        print(f"{args.name}: {out.strip()}")
        return 0
    # Fall back to the sysv `service` command for hosts without systemd
    out2, rc2 = docker_exec(args.host, ["service", args.name, "status"])
    if rc2 == 0:
        print(f"{args.name}: active (sysv)")
        return 0
    print(f"{args.name}: missing or unmanaged")
    return 0


def cmd_connection_list(args: argparse.Namespace) -> int:
    """List currently established TCP connections (no process attribution)."""
    out, rc = docker_exec(args.host, ["ss", "-tn", "state", "established"])
    if rc != 0:
        print(out, file=sys.stderr)
        return 1
    print(out)
    return 0


# ---------------------------------------------------------------------------
# Argparse plumbing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="host_query.py",
        description=(
            "Constrained read-only host query CLI for playground containers. "
            "Select the target host via --host."
        ),
    )
    p.add_argument(
        "--host",
        choices=ALLOWED_HOSTS,
        default=DEFAULT_HOST,
        help=(
            f"Which playground host to inspect. Default: {DEFAULT_HOST}. "
            f"Allowed: {', '.join(ALLOWED_HOSTS)}."
        ),
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    s = sub.add_parser(
        "process-list",
        help="List running process names matching a pattern (names only — no argv)",
    )
    s.add_argument("pattern")
    s.set_defaults(func=cmd_process_list)

    s = sub.add_parser(
        "listening-sockets",
        help="List currently listening TCP and UDP sockets",
    )
    s.set_defaults(func=cmd_listening_sockets)

    s = sub.add_parser(
        "file-stat",
        help="Stat a file (metadata only — never contents). Refuses playground answer-key paths.",
    )
    s.add_argument("path")
    s.set_defaults(func=cmd_file_stat)

    s = sub.add_parser(
        "package-installed",
        help="Check if a debian package is installed",
    )
    s.add_argument("name")
    s.set_defaults(func=cmd_package_installed)

    s = sub.add_parser(
        "service-status",
        help="Check service status (systemd or sysv)",
    )
    s.add_argument("name")
    s.set_defaults(func=cmd_service_status)

    s = sub.add_parser(
        "connection-list",
        help="List established TCP connections (no process attribution)",
    )
    s.set_defaults(func=cmd_connection_list)

    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
