"""Test-only fakes for the lab periphery contract (lock store over `docker exec`, capture timing).

A local shell stands in for the lab container; nothing here knows what a lock record looks like.
Imports `_lab_fakes` read-only.
"""
from __future__ import annotations

import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from _lab_fakes import FakeLockStore

_PATH = re.compile(r"(?<![\w./~$-])/[A-Za-z0-9_.][^\s'\"`;|&<>()$\\]*")
_PASSTHROUGH = ("/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr")


def reroot(text: str, root: str) -> str:
    """Re-root absolute paths under `root`, so a lab-container script acts on a throwaway dir."""
    def sub(m: re.Match) -> str:
        path = m.group(0)
        if path == root or path.startswith(root + "/") or path in _PASSTHROUGH:
            return path
        return root + path
    return _PATH.sub(sub, text)


class LocalContainer:
    """Stands in for `docker --context C exec [opts] CONTAINER <argv>`: runs the argv here,
    re-rooted under `root`. Records every argv. Knows nothing about locks."""

    def __init__(self, root: Path) -> None:
        self.root, self.argvs = root, []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.argvs.append(list(argv))
        assert argv[:2] == ["docker", "--context"] and argv[3] == "exec", argv
        rest, i = list(argv[4:]), 0
        while rest[i].startswith("-"):  # docker exec options: -i, -u X, -e K=V, -w D
            i += 2 if rest[i] in ("-u", "-e", "-w", "--user", "--env", "--workdir") else 1
        inner = [reroot(a, str(self.root)) for a in rest[i + 1:]]  # rest[i] is the container
        assert inner and "/" not in inner, argv
        run_kwargs = {k: v for k, v in kwargs.items() if k in ("input", "stdin", "timeout")}
        return subprocess.run(inner, capture_output=True, text=True, **run_kwargs)


_DOCKER_SHIM = '''#!{python}
import json, os, subprocess, sys
sys.path.insert(0, {here!r})
from _periphery_fakes import LocalContainer
from pathlib import Path
box = LocalContainer(Path({root!r}))
done = box(["docker", *sys.argv[1:]], input=None if sys.stdin.isatty() else sys.stdin.read())
with open({log!r}, "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
sys.stdout.write(done.stdout); sys.stderr.write(done.stderr)
sys.exit(done.returncode)
'''


def install_fake_docker(bin_dir: Path, root: Path) -> Path:
    """Write an executable `docker` into `bin_dir` that behaves as `LocalContainer(root)` and logs
    each argv (one JSON list per line) to the returned file. Put `bin_dir` first on PATH."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = bin_dir / "docker-argv.log"
    shim = bin_dir / "docker"
    shim.write_text(_DOCKER_SHIM.format(python=sys.executable, here=str(Path(__file__).parent),
                                        root=str(root), log=str(log)))
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return log


class TimedLockStore(FakeLockStore):
    """`FakeLockStore` that also stamps the clock reading at each create and delete, so a test
    can read how long a lock was held in the capture's own (fake) time."""

    def __init__(self, journal, clock) -> None:
        super().__init__(journal)
        self.clock, self.created_at, self.deleted_at = clock, {}, {}

    def create_exclusive(self, name: str, record: str) -> bool:
        won = super().create_exclusive(name, record)
        if won:
            self.created_at[name] = self.clock.last
        return won

    def delete(self, name: str) -> None:
        self.deleted_at[name] = self.clock.last
        super().delete(name)


def containers_in(log: Path) -> set[str]:
    """The containers a fake-docker log shows commands sent to (docker exec options skipped)."""
    import json
    found: set[str] = set()
    for line in log.read_text().splitlines() if log.exists() else []:
        rest, i = json.loads(line)[3:], 0  # after: --context <ctx> exec
        while rest[i].startswith("-"):
            i += 2 if rest[i] in ("-u", "-e", "-w", "--user", "--env", "--workdir") else 1
        found.add(rest[i])
    return found
