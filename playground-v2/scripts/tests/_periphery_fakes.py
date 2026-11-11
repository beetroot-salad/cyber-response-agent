"""Test-only fakes for the lab periphery contract (lock store over `docker exec`, capture timing).

A local shell stands in for the lab container; nothing here knows what a lock record looks like.
Imports `_lab_fakes` read-only.
"""
from __future__ import annotations

import re
import shlex
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


# -- docker, as the real lab operations see it ---------------------------------------------------

_VALUE_OPTS = {"--name", "-e", "--env", "-v", "--volume", "-p", "--publish", "--network", "--net", "-w",
               "--workdir", "-u", "--user", "--add-host", "--env-file", "--entrypoint", "-l", "--label",
               "--restart", "-m", "--memory", "--cpus", "-h", "--hostname", "--ip", "--dns", "--mount",
               "--log-driver", "--pid", "--cap-add", "--cap-drop", "--security-opt", "--ulimit",
               "--tmpfs", "--device", "--group-add", "--platform", "--pull", "--health-cmd", "--network-alias"}
_GLOBAL_OPTS = {"--context", "-c", "-H", "--host", "--config", "-l", "--log-level"}


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


class FakeDocker:
    """A `run=` that behaves as the docker CLI does for the container life cycle, and records every call.

    Models: `run` (detached = running; foreground = ran and exited; `--rm` removes it), `create`,
    `start`, `restart`, `stop`, `kill`, `rm [-f]` (a running container needs `-f`; `-f` on a missing
    one is silent), and `exec` with a nested `docker ...` (also inside `sh -c "..."`), which acts on
    the engine inside that container (a different scope). A container the model has not seen but
    that a command names is taken to exist already, running (the deployed stack). Nothing else
    changes state; every other verb succeeds with empty output. A verb that creates or removes
    containers in a way the model does not parse (`compose`, `swarm`, `service`, `stack`) is listed
    in `unmodelled`, so a test says so instead of passing on a container it never saw.

    `running()` is `{(scope, name)}` now; `started` is every container a `run -d`, `start`,
    `restart` or `create`+`start` brought up, whether or not it still runs."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.state: dict[tuple[str, str], str] = {}     # (scope, name) -> running | exited | created
        self.started: set[tuple[str, str]] = set()
        self.unmodelled: list[str] = []
        self._anon = 0

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        failure = self._docker([str(a) for a in argv], "", kw)
        rc, out, err = failure if failure else (0, "", "")
        done = subprocess.CompletedProcess(argv, rc, stdout=out, stderr=err)
        if rc and kw.get("check"):
            raise subprocess.CalledProcessError(rc, argv, output=out, stderr=err)
        return done

    def running(self) -> set[tuple[str, str]]:
        return {k for k, v in self.state.items() if v == "running"}

    def _docker(self, argv: list[str], scope: str, kw: dict):
        if not argv or argv[0] != "docker":
            return None
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            i += 2 if argv[i] in _GLOBAL_OPTS else 1
        if i >= len(argv):
            return None
        verb, rest = argv[i], argv[i + 1:]
        if verb in ("run", "create"):
            return self._run(verb, rest, scope)
        if verb in ("start", "restart", "stop", "kill", "rm", "exec"):
            names = [a for a in rest if not a.startswith("-")]
            if verb == "exec":
                return self._exec(rest, scope, kw)
            return self._lifecycle(verb, rest, names, scope)
        if verb in ("compose", "swarm", "service", "stack"):
            self.unmodelled.append(" ".join(argv))
        return None

    def _run(self, verb: str, rest: list[str], scope: str):
        name, detach, remove, j = None, False, False, 0
        while j < len(rest) and rest[j].startswith("-"):
            opt = rest[j]
            if opt.startswith("--name="):
                name = opt.split("=", 1)[1]
            elif opt == "--name":
                name, j = rest[j + 1], j + 1
            elif opt in ("-d", "--detach"):
                detach = True
            elif opt == "--rm":
                remove = True
            elif opt in _VALUE_OPTS:
                j += 1
            j += 1
        out = ""
        if name is None:
            self._anon += 1
            name = f"anon{self._anon:04d}"
            out = f"{name}\n"
        key = (scope, name)
        if key in self.state and self.state[key] != "removed":
            return 125, "", f"Conflict. The container name \"{name}\" is already in use"
        if verb == "create":
            self.state[key] = "created"
        elif detach:
            self.state[key] = "running"
            self.started.add(key)
        else:
            self.state[key] = "exited"
        if remove and not detach and verb == "run":
            del self.state[key]
        return 0, out, ""

    def _lifecycle(self, verb: str, rest: list[str], names: list[str], scope: str):
        force = any(a in ("-f", "--force") for a in rest)
        for name in names:
            key = (scope, name)
            if key not in self.state:
                if verb == "rm" and force:
                    continue
                self.state[key] = "running"          # deployed before the test began
            current = self.state[key]
            if verb in ("start", "restart"):
                self.state[key] = "running"
                self.started.add(key)
            elif verb in ("stop", "kill"):
                if current == "running":
                    self.state[key] = "exited"
            elif verb == "rm":
                if current == "running" and not force:
                    return 1, "", f"Error response from daemon: cannot remove container \"{name}\": container is running"
                del self.state[key]
        return None

    def _exec(self, rest: list[str], scope: str, kw: dict):
        j = 0
        while j < len(rest) and rest[j].startswith("-"):
            j += 2 if rest[j] in ("-u", "-e", "-w", "--user", "--env", "--workdir") else 1
        if j >= len(rest):
            return None
        container, command = rest[j], rest[j + 1:]
        key = (scope, container)
        self.state.setdefault(key, "running")
        if self.state[key] != "running":
            return 1, "", f"Error response from daemon: container {container} is not running"
        inner = (scope + "/" if scope else "") + container
        commands = [command]
        if len(command) >= 3 and command[0].rsplit("/", 1)[-1] in ("sh", "bash") and command[1].endswith("c"):
            commands = [_words(part) for part in re.split(r"&&|\|\||;|\n", command[2]) if part.strip()]
        result = None
        for cmd in commands:
            result = self._docker(cmd, inner, kw) or result
            if result and result[0]:
                return result
        return result
