"""Shared docker fakes and box-geography helpers for the box tests (#665 and later)."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender import box as box_mod
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.sandbox._docker import daemon_reachable, is_dood
from defender.tests.e2e._local_box_command import run_box_python_command

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent


# Live-box skip, mirroring test_540: no daemon, or docker-outside-of-Docker (bind sources resolve
# on the daemon host, invisible here). `live`-marked users are deselected in CI (`-m "not live"`).
_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()

requires_live_box = pytest.mark.skipif(
    _NO_DAEMON or _DOOD,
    reason=("needs a native docker daemon that can bind this process's filesystem "
            "(no daemon, or docker-outside-of-Docker where bind sources are invisible)"),
)


# The declarative docker fake: daemon faults are data citing the ledger claim that observed
# them on a real box. box.py's real argv build and framing run unchanged, so geography tests
# assert on `create_argv`.
def _cp(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["docker"], returncode=rc, stdout=out, stderr=err)


def framed(rc: int, out: bytes = b"", err: bytes = b"") -> box_mod.RawExec:
    """A RawExec carrying a well-formed response frame, as if the in-box entrypoint ran; the
    real framing codec decodes it."""
    return box_mod.RawExec(
        rc=rc, stdout=box_mod.encode_response(box_mod.BoxResult(rc=rc, out=out, err=err)),
        stderr=b"",
    )


class ScriptedTransport:
    """An injected box transport (BoxExecutor(transport=…)): records the frames it received
    and replies from a script. A reply is a RawExec (returned) or a BaseException instance
    (raised — models a transport that could not reach the daemon). Never classifies."""

    def __init__(self, *replies):
        self._replies = list(replies) or [framed(0)]
        self.calls: list = []

    def __call__(self, frame: bytes, *, cwd, timeout) -> box_mod.RawExec:
        self.calls.append((frame, cwd, timeout))
        r = self._replies[min(len(self.calls) - 1, len(self._replies) - 1)]
        if isinstance(r, BaseException):
            raise r
        return r


@dataclass(frozen=True)
class DockerFault:
    """One docker subcommand's declarative failure. `cite` is the ledger claim id that
    OBSERVED this rc/stderr on a real daemon (never an author guess)."""

    rc: int
    stderr: str = ""
    stdout: str = ""
    cite: str = ""


class RecordingDocker:
    """Injectable `docker` fn for `start_box(..., docker=…)`.

    Records every argv and models a healthy daemon unless a declared fault is supplied:
    no same-name container, successful create and sentinel readback. Tenant-marker reads
    execute the actual supplied command locally, with the operand translated through the
    captured bind mounts; the fake neither parses marker bytes nor supplies an identity.
    Alias probes retain their scripted verdicts. No live container is created."""

    def __init__(
        self, *, create: DockerFault | None = None,
        sentinel: DockerFault | None = None, reap: DockerFault | None = None,
        exec_replies: list | None = None, existing_token: str | None = None,
        status: str | None = None,
    ):
        # What `docker inspect -f {{.State.Status}}` answers: docker's own word, or None for a
        # free name (rc 1, as a real daemon answers). A word, not a bool, so it can say `created`.
        self.status = status
        # The start-token label `docker inspect` finds under this name (the ownership check):
        #   None     no such container
        #   "self"   the container THIS start created (create-then-start leak): the only one a
        #            fault arm may reap
        #   <other>  another lane's box that won a name race: it must survive
        self.existing_token = existing_token
        self.create = create            # DockerFault on `docker run` (create)
        self.sentinel = sentinel        # DockerFault on the sentinel exec readback
        self.reap = reap                # DockerFault on `docker rm -f`
        self._exec_replies = list(exec_replies or [])
        self.calls: list[list[str]] = []
        self.create_argv: list[str] | None = None

    def _inspect(self, argv: list[str]) -> subprocess.CompletedProcess:
        """`docker inspect` answers three questions, told apart by the format string as on a
        real daemon: the container's state (`-f {{.State.Status}}`), its start-token label
        (`-f {{index .Config.Labels …}}`) and this process's mount table (`--format …`)."""
        if "-f" not in argv:
            # `--format`: the DooD mount table, empty: this double models a container name, not
            # this process's own bind mounts.
            return _cp(0, "")
        fmt = argv[argv.index("-f") + 1]
        if "Config.Labels" not in fmt:
            if self.status is not None:
                return _cp(0, f"{self.status}\n")
            return _cp(1, "", "No such object\n")
        if self.existing_token is None:
            return _cp(1, "", "No such object\n")
        token = self.existing_token
        if token == "self":
            # Echo the token THIS start stamped, read off the captured argv so a token box.py
            # never sent cannot pass the ownership check. `<no value>` is docker's own text.
            token = self.create_label(box_mod.START_TOKEN_LABEL) or "<no value>"
        return _cp(0, f"{token}\n")

    def _read_marker(self, argv: list[str]) -> subprocess.CompletedProcess:
        """Execute a marker read through the captured bind table, with nested mounts winning."""
        marker = Path(argv[-1])
        covering = [
            mount for mount in self.mounts()
            if mount["source"] and mount["target"]
            and marker.is_relative_to(Path(mount["target"]))
        ]
        assert covering, f"no captured bind mount covers the marker read at {marker}"
        mount = max(covering, key=lambda item: len(Path(item["target"]).parts))
        source = Path(mount["source"]) / marker.relative_to(Path(mount["target"]))
        command = [*argv[-4:-1], str(source)]
        return run_box_python_command(command)

    def _through_binds(self, inside: Path) -> Path:
        """Where an in-box path lives on the host, through the captured bind table (nested
        mounts winning); unchanged when no bind covers it. The box mounts each tree at a fixed
        model path (`/runs/current`, …), so an in-box path is not the host path."""
        if self.create_argv is None:
            return inside
        covering = [m for m in self.mounts()
                    if m["source"] and m["target"] and inside.is_relative_to(Path(m["target"]))]
        if not covering:
            return inside
        mount = max(covering, key=lambda item: len(Path(item["target"]).parts))
        return Path(mount["source"]) / inside.relative_to(Path(mount["target"]))

    def _exec(self, argv: list[str]) -> subprocess.CompletedProcess:
        if argv[-4:-2] == ["python3", "-c"] and argv[-1].endswith("/.tenant-id"):
            return self._read_marker(argv)
        if "python3" in argv and "-c" in argv:
            # The #771 alias-ban probe runs at every box start. Tests that care about its
            # verdict use `_spec771.AliasProbeDocker`; everyone else gets the healthy verdict.
            if self._exec_replies:
                return self._exec_replies.pop(0)
            return _cp(0, "alias-probe: all banned shapes denied; ordinary create ok\n", "")
        if self.sentinel is not None:
            return _cp(self.sentinel.rc, self.sentinel.stdout, self.sentinel.stderr)
        if self._exec_replies:
            return self._exec_replies.pop(0)
        path = self._through_binds(Path(argv[-1]))   # sentinel readback: `cat <sentinel>`
        try:
            return _cp(0, path.read_text(encoding="utf-8"))
        except OSError:
            return _cp(1, "", "cat: no such file or directory\n")

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.calls.append(argv)
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "inspect":
            return self._inspect(argv)
        if sub == "rm":
            f = self.reap
            return _cp(f.rc, f.stdout, f.stderr) if f else _cp(0)
        if sub == "run":
            self.create_argv = argv
            f = self.create
            return _cp(f.rc, f.stdout, f.stderr) if f else _cp(0, "container-id\n")
        if sub == "exec":
            return self._exec(argv)
        return _cp(0)

    # argv readers (parse the captured `docker run` argv)
    def _argv(self) -> list[str]:
        assert self.create_argv is not None, "docker create was never invoked"
        return self.create_argv

    def mounts(self) -> list[dict]:
        """Every `--mount type=bind,...` spec on the create argv, as a parsed dict with
        keys source/target/readonly."""
        out: list[dict] = []
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == "--mount" and i + 1 < len(argv):
                spec = argv[i + 1]
                parts = dict(
                    p.split("=", 1) for p in spec.split(",") if "=" in p
                )
                out.append({
                    "source": parts.get("source", ""),
                    "target": parts.get("target", ""),
                    "readonly": "readonly" in spec.split(","),
                })
        return out

    def env(self) -> dict[str, str]:
        """The rendered `--env KEY=VALUE` pairs on the create argv."""
        out: dict[str, str] = {}
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == "--env" and i + 1 < len(argv):
                k, _, v = argv[i + 1].partition("=")
                out[k] = v
        return out

    def flag_value(self, flag: str) -> str | None:
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == flag and i + 1 < len(argv):
                return argv[i + 1]
        return None

    def has_flag(self, flag: str) -> bool:
        return flag in self._argv()

    def create_label(self, key: str) -> str | None:
        """The value `docker run --label <key>=…` carried on the captured create argv (read off
        the argv, never stored, so the ownership check sees only what box.py stamped)."""
        for i, tok in enumerate(self._argv()):
            if tok == "--label" and i + 1 < len(self._argv()):
                k, _, v = self._argv()[i + 1].partition("=")
                if k == key:
                    return v
        return None

    def tmpfs(self) -> str | None:
        return self.flag_value("--tmpfs")


def reaped_after_create(calls) -> bool:
    """Whether the container the create asked for was reaped after the create."""
    create = next(
        (i for i, c in enumerate(calls) if len(c) > 1 and c[1] == "run"), None
    )
    assert create is not None, "no `docker run` was issued — the fault fired before create"
    argv = calls[create]
    name = argv[argv.index("--name") + 1]
    return ["docker", "rm", "-f", name] in calls[create + 1:]


# The box.py geography seam: callers compose the geography, box.py renders and validates it.
def Mount(source: Path, target: Path, writable: bool = False, kind: str | None = None):
    """`box.Mount`. `kind` (`code`, `agent` or `data`: what a read-only mount holds) is passed
    only when given, so a writable mount names none."""
    kw: dict[str, Any] = dict(source=source, target=target, writable=writable)
    if kind is not None:
        kw["kind"] = kind
    return box_mod.Mount(**kw)  # type: ignore[attr-defined]


def run_cycle_mounts(run_dir: Path) -> tuple:
    """A minimal caller-composed run-cycle geography: the run dir, the defender code tree and
    the gather_raw evidence, each read-only and declaring its `kind`."""
    return (
        Mount(source=run_dir, target=run_dir, writable=False, kind="data"),
        Mount(source=DEFENDER, target=DEFENDER, writable=False, kind="code"),
        Mount(source=run_dir / "gather_raw", target=run_dir / "gather_raw", writable=False,
              kind="data"),
    )


def BoxRequest(*, name: str, mounts, workdir: Path, env, spec=None, defender_dir=None):
    """`box.BoxRequest`, the caller-owned geography box.py renders. `spec` and `defender_dir`
    (the explicit code root) are passed only when given."""
    kw: dict[str, Any] = dict(name=name, mounts=tuple(mounts), workdir=workdir, env=dict(env))
    if spec is not None:
        kw["spec"] = spec
    if defender_dir is not None:
        kw["defender_dir"] = defender_dir
    return box_mod.BoxRequest(**kw)  # type: ignore[attr-defined]


def start_box_request(request, *, docker):
    """`box.start_box(request, docker=…)` over a caller-composed `BoxRequest`."""
    return box_mod.start_box(request, docker=docker)  # type: ignore[call-arg]


# Lifecycle seams: callers take injectable `start_box`/`stop_box` (box.py's own names), so a
# test observes creation geography, delivery to the roles and teardown order without a daemon.
@dataclass
class FakeBox:
    """A stand-in BoxExecutor a creation seam produced — identity is what tests assert."""

    name: str = "box-665"
    request: Any = None
    #: False: no container stands behind it, so the drain's `BoxRuns` handle treats it as the
    #: opt-out and asks no daemon (True would fault: it carries no docker).
    sandboxed: bool = False


class BoxLifecycleRecorder:
    """Injectable `start_box`/`stop_box` pair. `start_box(request)` records the composed
    geography and returns a FakeBox; `stop_box(box)` records teardown order (and can fault
    to model a failed teardown). Records nothing about policy."""

    def __init__(self, *, stop_fault: Exception | None = None, events: list | None = None):
        self.requests: list = []
        self.boxes: list[FakeBox] = []
        self.stopped: list[FakeBox] = []
        self.scrubbed: list = []
        self.events: list[str] = events if events is not None else []
        self._stop_fault = stop_fault

    def start_box(self, request, *_a, **_kw) -> FakeBox:
        b = FakeBox(name=getattr(request, "name", "box-665"), request=request)
        self.requests.append(request)
        self.boxes.append(b)
        self.events.append(f"start:{b.name}")
        return b

    def stop_box(self, box, *_a, **_kw) -> None:
        self.events.append(f"stop:{getattr(box, 'name', '?')}")
        self.stopped.append(box)
        if self._stop_fault is not None:
            raise self._stop_fault

    def scrub(self, path, *_a, **_kw) -> None:
        """Injectable `scrub=` seam: records only the scan's order in the shared event log (the
        scan itself is pinned over a real tree)."""
        self.events.append(f"scrub:{path}")
        self.scrubbed.append(path)

    def only_request(self):
        assert len(self.requests) == 1, (
            f"expected exactly ONE box created for the invocation, got {len(self.requests)}"
        )
        return self.requests[0]


# run_dir / learning setup for driving the run cycle.
def make_run_dir(tmp_path: Path, *, disposition: str = "inconclusive") -> Path:
    """A finished run dir: alert, report.md (its disposition picks which legs dispatch),
    investigation.md and gather_raw/ holding one result for read-back."""
    run_dir = tmp_path / "inv-665"
    run_dir.mkdir(parents=True)
    (run_dir / "gather_raw").mkdir()
    (run_dir / "gather_raw" / "fixture.json").write_text("{}\n", encoding="utf-8")
    plant_alert(run_dir, {"rule": {"key": "spec.rule"}})
    (run_dir / "report.md").write_text(
        f"---\ndisposition: {disposition}\n---\n\nspec run\n", encoding="utf-8"
    )
    (run_dir / "investigation.md").write_text("+ spec investigation\n", encoding="utf-8")
    return run_dir


def _path_matches(value, needle: str) -> bool:
    """Does `value` (a path) match `needle`?"""
    p = Path(str(value))
    n = Path(needle)
    if n.is_absolute():
        return p == n or p.is_relative_to(n)
    want, have = n.parts, p.parts
    if not want:
        return False
    return any(
        have[i:i + len(want)] == want for i in range(len(have) - len(want) + 1)
    )


def mount_for(request, needle: str):
    """The Mount on `request` whose source or target matches `needle` (None if unmounted).

    `needle` is an absolute path (matched by identity) or a single path component (matched
    whole — see `_path_matches`).
    """
    for m in getattr(request, "mounts", ()):
        if _path_matches(getattr(m, "source", ""), needle) or \
                _path_matches(getattr(m, "target", ""), needle):
            return m
    return None


