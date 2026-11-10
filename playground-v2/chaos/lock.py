#!/usr/bin/env python3
"""Lab-wide locks held on the lab server: the capture lock and the frozen engine's run lock.

A lock is one record on the VPS, written with an atomic exclusive create and read over the same
`docker --context soc-playground exec` connection the runner uses, so it holds whichever operator
machine fires the runner (#1347 D14). Taking a free lock returns a random token; only the holder
passes it on. `require` is the check the attack runner and the chaos control's `activate` make:
a held lock refuses unless handed the holder's token.

A lock never expires. A dead holder's lock is cleared by the operator, explicitly:

    python3 chaos/lock.py status capture
    python3 chaos/lock.py clear capture

`store=` is injectable so tests never need the live stack. A store offers
`create_exclusive(name, record) -> bool`, `read(name) -> str | None`, `delete(name)` and
`delete_if_held_by(name, token) -> bool`: the holder check and the delete in one step on the lab
server, so a lock cleared and retaken meanwhile keeps its new holder (`release` frees through it).
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import secrets
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

CAPTURE = "capture"
FROZEN_ENGINE = "frozen-engine"

DOCKER_CONTEXT = "soc-playground"
# Always running, and not one of the hosts whose filesystem the agent reads. The record lives in
# the container's writable layer: it survives a restart, not a recreate.
LOCK_CONTAINER = "elasticsearch"
LOCK_DIR = "/tmp/lab-locks"

_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_TOKEN = re.compile(r"[0-9a-f]{8,64}")


class LockError(RuntimeError):
    """Base of the lock refusals."""


class Held(LockError):
    """The lock is held by someone else (or by a holder whose token was not passed)."""


class WrongToken(LockError):
    """A token was passed, but it is not the holder's."""


_UNREADABLE = object()


def _token_of(record: Optional[str]) -> Any:
    if record is None:
        return None
    try:
        return json.loads(record).get("token")
    except (ValueError, AttributeError):
        # An unreadable record still holds the lock; no token, not even "", can match it.
        return _UNREADABLE


def take(store: Any, name: str, *, clock: Callable[[], float] = time.time) -> str:
    """Take `name` and return its token, or raise Held. One exclusive create: atomic."""
    token = secrets.token_hex(16)
    record = json.dumps({
        "token": token,
        "taken_at": datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds"),
        "holder": f"{getpass.getuser()}@{socket.gethostname()}",
    })
    if not store.create_exclusive(name, record):
        raise Held(f"lock {name!r} is held: {_describe(store.read(name))}")
    return token


def release(store: Any, name: str, token: str) -> None:
    """Free `name` if `token` is the holder's; a wrong token raises WrongToken and keeps it.
    One check-and-delete on the store: there is no gap between reading the holder and deleting."""
    if store.delete_if_held_by(name, token):
        return
    if store.read(name) is not None:
        raise WrongToken(f"lock {name!r}: the token passed is not the holder's")


def require(store: Any, name: str, token: Optional[str] = None) -> None:
    """Pass when `name` is free or `token` is the holder's; raise Held / WrongToken otherwise."""
    record = store.read(name)
    if record is None:
        return
    if token is None:
        raise Held(f"lock {name!r} is held: {_describe(record)}; pass the holder's --lock-token")
    if _token_of(record) != token:
        raise WrongToken(f"lock {name!r} is held and the token passed is not the holder's")


def clear(store: Any, name: str) -> None:
    """The operator's explicit clear of a dead holder's lock. No token needed."""
    store.delete(name)


def _describe(record: Optional[str]) -> str:
    if record is None:
        return "released meanwhile"
    try:
        parsed = json.loads(record)
        return f"taken {parsed.get('taken_at')} by {parsed.get('holder')}"
    except (ValueError, AttributeError):
        return "unreadable record"


class DockerLockStore:
    """The lab-server store: one file per lock in `LOCK_DIR` inside `LOCK_CONTAINER`.

    Every take, release and clear of a record runs under `flock` on the record's own lock file
    (`<record>.lock`), so a release's token comparison and its delete are one locked step: no
    clear and retake can come between them. The exclusive create is also the shell's noclobber
    redirect (O_EXCL). Exit 3 means "already there" (create), "absent" (read) or "not this
    holder's" (release); any other non-zero exit is a transport failure and raises, so an
    unreachable lab never reads as a free lock. `run=` replaces subprocess.run.
    """

    # Opens the record's lock file on fd 9 and holds it until the shell ends.
    _LOCKED = 'mkdir -p "$(dirname "$1")" || exit 4; exec 9>>"$1.lock" || exit 4; flock -x 9 || exit 4; '

    def __init__(self, run: Any = subprocess.run, *, context: str = DOCKER_CONTEXT,
                 container: str = LOCK_CONTAINER, directory: str = LOCK_DIR) -> None:
        self._run, self._context, self._container, self._dir = run, context, container, directory

    def _path(self, name: str) -> str:
        if not _NAME.match(name):
            raise ValueError(f"bad lock name {name!r}")
        return f"{self._dir}/{name}"

    def _sh(self, script: str, *args: str) -> Any:
        argv = ["docker", "--context", self._context, "exec", self._container,
                "sh", "-c", script, "sh", *args]
        return self._run(argv, capture_output=True, text=True)

    def _fail(self, what: str, proc: Any) -> LockError:
        return LockError(f"lock store {what}: rc={proc.returncode} {(proc.stderr or '').strip()}")

    def create_exclusive(self, name: str, record: str) -> bool:
        script = (self._LOCKED + 'set -C; '
                  'if printf "%s" "$2" > "$1" 2>/dev/null; then exit 0; fi; '
                  '[ -e "$1" ] && exit 3; exit 4')
        proc = self._sh(script, self._path(name), record)
        if proc.returncode == 0:
            return True
        if proc.returncode == 3:
            return False
        raise self._fail(f"create {name}", proc)

    def read(self, name: str) -> Optional[str]:
        proc = self._sh('[ -e "$1" ] || exit 3; cat "$1"', self._path(name))
        if proc.returncode == 3:
            return None
        if proc.returncode != 0:
            raise self._fail(f"read {name}", proc)
        return proc.stdout

    def delete(self, name: str) -> None:
        proc = self._sh(self._LOCKED + 'rm -f "$1"', self._path(name))
        if proc.returncode != 0:
            raise self._fail(f"delete {name}", proc)

    def delete_if_held_by(self, name: str, token: str) -> bool:
        """Delete the record only if it carries `token`: compared and deleted under the record's
        flock, in one exec. Exit 3: absent, or another holder's; nothing deleted."""
        if not _TOKEN.fullmatch(token or ""):
            return False      # `take` makes hex tokens; anything else holds nothing
        script = (self._LOCKED + '[ -e "$1" ] || exit 3; '
                  'grep -qF "\\"token\\": \\"$2\\"" "$1" || exit 3; rm -f "$1" || exit 4')
        proc = self._sh(script, self._path(name), token)
        if proc.returncode == 0:
            return True
        if proc.returncode == 3:
            return False
        raise self._fail(f"release {name}", proc)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lab-wide locks on the lab server")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, text in (("status", "show who holds a lock"),
                          ("clear", "clear a dead holder's lock (no token needed)")):
        p = sub.add_parser(command, help=text)
        p.add_argument("name", choices=(CAPTURE, FROZEN_ENGINE))
    args = parser.parse_args(argv)
    store = DockerLockStore()
    if args.command == "status":
        record = store.read(args.name)
        print("free" if record is None else _describe(record))
        return 0
    clear(store, args.name)
    print(f"cleared {args.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
