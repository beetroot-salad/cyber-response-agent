"""#1188 — the box file-size cap: M1 (`--ulimit fsize=L:L` on both box `docker run` argvs),
M2 (the box cannot lift it) and M3 (proved on a live box, under both runtimes: an investigation
box through the exec path the agent's commands take, and a lane box built the way a drain
builds one) — plus core dumps off on both argvs.

The obligations, from the design comment on #1188:

* O1 — no file a box writes on a writable mount can exceed the host's whole-file read cap
  (`_io.READ_LIMIT`). Apparent size is what counts, so a sparse file is no exception, and nor
  is an allocated one (`fallocate`).
* O2 — O1 holds on BOTH launch paths (the investigation box, `_create_argv`; the lane boxes,
  `_render_argv` via `BoxRequest`) and for every process in the box, including the commands
  `docker exec` brings in (`BoxExecutor.run_parsed`).
* O3 — the box cannot lift the limit (`ulimit -Hf unlimited` inside it fails).

And from the review of #1198, which settled two more points:

* NO KNOB. The cap is not a `BoxSpec` field: it is always `_io.READ_LIMIT`, in bytes (Docker's
  unit, C3), read from `_io` rather than restated as a second literal. The field existed only
  so tests could set a small limit; without it a -1, 0 or oversized limit cannot be configured
  at all. Pinned twice: `BoxSpec` refuses the old keyword and names no file-size field, and
  moving the read cap before the box package loads moves both argvs.
* CORE DUMPS OFF. Both argvs carry `--ulimit core=0:0` (two tokens, once, before the image).
  The kernel kills an over-cap writer with SIGXFSZ, whose default action dumps core, and a
  core file lands in the dying process's cwd — a run dir, or a drain lane's writable tree: a
  file on a host-read tree that no command in the box chose to write. Pinned on both argvs and,
  live, by `getrlimit(RLIMIT_CORE) == (0, 0)` in the box (the live `core*` scan beside it
  cannot fail on most hosts; see `_assert_a_writer_the_cap_kills_leaves_no_core`).

So the interface pinned here: both argvs carry `--ulimit fsize=<L>:<L>` with L =
`_io.READ_LIMIT`, then `--ulimit core=0:0` (test_1092's hand-written argv pins that order,
right after the seccomp profile), and `BoxSpec` takes no keyword that sets either.

RED AT `1b29a449` (the fsize flag rendered from `BoxSpec.file_size_limit`; no core flag):

* the core argv tests — no `--ulimit core=…` on either argv;
* `test_the_box_spec_has_no_knob_for_the_file_size_cap` — `BoxSpec(file_size_limit=...)`
  constructs;
* the live dumps-no-core tests — `RLIMIT_CORE` reads `[-1, -1]` (unlimited) in the box.

GREEN AT `1b29a449`, and meant to be: the fsize argv tests, the follows-the-read-cap test and
the live cannot-make-a-file tests. They pin properties the current code already has and the
change must keep while it removes the field. That includes the `fallocate` checks: they pin a
kernel property (every apparent-size change is judged against `RLIMIT_FSIZE`), not new code.
Every negative in them was seen failing by hand under runc against a box with no fsize limit
(C3 for truncate/ftruncate/write/lift; `fallocate -l` and `posix_fallocate` a MiB past the
cap land whole).

THE TWO LIVE BOXES. The investigation box is `start_box(run_dir, DEFENDER, ...)`, and its
commands go through `BoxExecutor.run_parsed`, as the agent's do. The lane box is the lead-author
drain's: `drains._drain_box_request` over a throwaway git worktree (test_1178's shape), so it
mounts that worktree read-only and its `skills/` read-write, and nothing of this checkout — a
startup sentinel planted at a mount source lands in the throwaway tree. That worktree carries
no `defender` package for the in-box runner to import, so lane commands are plain
`docker exec` (`sh -c`, `python3 -c`), as test_1178 drives its box; the cap is the container's,
so every process `docker exec` starts holds it.

WHICH JOB RUNS THE LIVE TESTS. Like #771's mechanism confirmations they carry no
`@pytest.mark.live` (the gate's `-m "not live"` would deselect them and the `box-dood` job never
collects this file), so they run in CI's `test` job, which starts real boxes and registers runsc.
They are parametrized over BOTH runtimes because the load-bearing unknown of this design is
whether gVisor enforces `RLIMIT_FSIZE` (C4, unprobed): if `runsc` does not, these go red under
it and the design does not hold. A runtime the daemon does not register is skipped per case.

Fakes enter through `docker=` only. No `monkeypatch` anywhere.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import json
import os
import shutil
import signal
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from defender._io import READ_LIMIT
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.runtime import bash_exec, box as box_mod
from defender.runtime.box._image import HASH_INPUTS
from defender.tests._declared869 import commit_all, init_git
from defender.tests._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests._lead_author_1134 import write
from defender.tests.e2e._spec771 import AliasProbeDocker

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent

#: The box's file-size cap: always the host's whole-file read cap, in bytes.
L = READ_LIMIT

#: Docker's `--ulimit` unit for fsize is bytes (C3: `fsize=1048576` stopped `dd` at exactly
#: 1048576 bytes), so this is the value both argvs must carry.
FSIZE = f"fsize={L}:{L}"

#: Core dumps off, soft = hard: a hard limit of 0 leaves nothing to raise the soft one to.
CORE_OFF = "core=0:0"

#: Past the cap by a mebibyte: enough to be refused, and cheap if it is NOT refused — an
#: allocation or a real write this size lands whole rather than filling the host's disk.
PAST = L + (1 << 20)

#: Far past any cap, and cheap as a sparse extension (no data blocks). As an ALLOCATION it is
#: not cheap: `fallocate` really reserves the blocks, so a 1 TiB allocation is only ever tried
#: after the same primitive was refused at `PAST`.
ONE_TIB = 1 << 40

EXEC_TIMEOUT = 60.0


# ---- argv readers --------------------------------------------------------------------------

def _create_argv(rec: AliasProbeDocker) -> list[str]:
    assert rec.create_argv is not None, "start_box never issued `docker run`"
    return rec.create_argv


def _ulimits(argv: list[str], resource: str) -> list[str]:
    """Every `--ulimit <resource>=…` value on a captured create argv, in order. All of them,
    not the first `--ulimit`: a second flag (another resource, or the same one twice) must not
    hide the one the test is about."""
    return [
        argv[i + 1] for i, tok in enumerate(argv)
        if tok == "--ulimit" and i + 1 < len(argv) and argv[i + 1].startswith(f"{resource}=")
    ]


def _assert_one_ulimit(argv: list[str], resource: str, want: str, lane: str) -> None:
    """Exactly one `<resource>` ulimit, equal to `want`, and in OPTION position: `docker run`
    reads everything after the image as the container's command, so a flag appended after the
    image would be an argument to `sleep`, not a limit."""
    got = _ulimits(argv, resource)
    assert got == [want], (
        f"{lane}: the create argv carries {resource} ulimit(s) {got}, expected exactly "
        f"[{want!r}] — argv: {argv}"
    )
    assert argv[-2:] == ["sleep", "infinity"], f"{lane}: unexpected argv tail {argv[-3:]}"
    image_at = len(argv) - 3
    at = argv.index(want) - 1    # the `--ulimit` token `_ulimits` read the value after
    assert argv[at] == "--ulimit", f"{lane}: {want!r} is not the value of a `--ulimit` flag"
    assert at < image_at, (
        f"{lane}: `--ulimit {want}` sits at {at}, not before the image token at {image_at}, "
        f"so docker would hand it to the container's command instead of applying it"
    )


# ---- the two launch paths, driven through the real `start_box` with a recording daemon ------

def _run_dir(base: Path) -> Path:
    """A run dir whose NAME is unique: the investigation box's container name is derived from
    it, and a fixed name would collide with a concurrent test's box on a shared daemon."""
    run = base / f"run-1188-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True)
    return run


def _start_investigation(
    run_dir: Path, rec: AliasProbeDocker, *, tenant_agent: Path | None = None,
) -> None:
    """No `spec=`: the env-resolved default every investigation gets."""
    box_mod.start_box(run_dir, DEFENDER, tenant_agent=tenant_agent, docker=rec)


def _tenant_agent(base: Path) -> Path:
    """A tenant's agent half, as `run.py` always passes one: the production investigation box
    is never started without it, so a limit gated on its absence must not pass."""
    agent = base / f"tenant-agent-{uuid.uuid4().hex[:8]}"
    agent.mkdir(parents=True)
    return agent


def _start_lane(tmp_path: Path, rec: AliasProbeDocker, spec) -> None:
    """The lane path in #771's `_request` shape: a writable mount and an explicit rootfs (the
    tree is a scratch dir with no image hash inputs, and the daemon is scripted)."""
    src = tmp_path / "lane-wt"
    src.mkdir(parents=True, exist_ok=True)
    box_mod.start_box(
        box_mod.BoxRequest(
            # The name `drains._drain_box_request` gives a drain box, so a limit keyed on the
            # lane's name must not pass.
            name="defender-drain-1188",
            mounts=(box_mod.Mount(source=src, target=src, writable=True),),
            workdir=src, env={}, spec=spec,
        ),
        docker=rec,
    )


def _stock(spec):
    """`spec` with the stock image named, so the scripted lane needs no tree to resolve one."""
    return dataclasses.replace(spec, rootfs="python:3.11-slim")


def _both_argvs(tmp_path: Path) -> tuple[list[str], list[str]]:
    """The investigation box's and a lane box's create argvs, each on the env-resolved
    default spec (what `BoxRequest` resolves too), the investigation one with a tenant agent
    half."""
    inv = AliasProbeDocker()
    _start_investigation(_run_dir(tmp_path), inv, tenant_agent=_tenant_agent(tmp_path))
    lane = AliasProbeDocker()
    _start_lane(tmp_path, lane, _stock(box_mod.BoxSpec.from_env(os.environ)))
    return _create_argv(inv), _create_argv(lane)


@pytest.mark.parametrize("with_tenant", [True, False], ids=["tenant-agent", "no-tenant-agent"])
def test_the_investigation_box_launches_with_the_read_cap_as_its_file_size_limit(
    with_tenant, tmp_path,
):
    """O1/O2 (M1), investigation lane: `start_box(run_dir, defender_dir)` with no spec — the
    env-resolved default every investigation gets — issues a `docker run` carrying
    `--ulimit fsize=READ_LIMIT:READ_LIMIT`, once, soft equal to hard, in bytes, before the
    image. With and without the tenant's agent half: `run.py` always passes one."""
    rec = AliasProbeDocker()
    agent = _tenant_agent(tmp_path) if with_tenant else None
    _start_investigation(_run_dir(tmp_path), rec, tenant_agent=agent)
    _assert_one_ulimit(_create_argv(rec), "fsize", FSIZE, "investigation lane")


def test_a_lane_box_launches_with_the_read_cap_as_its_file_size_limit(tmp_path):
    """O1/O2 (M1), lane boxes: a `BoxRequest` on the env-resolved default spec (what
    `drains._drain_box_request` builds) issues a `docker run` carrying
    `--ulimit fsize=READ_LIMIT:READ_LIMIT`, once, before the image — and the SAME value the
    investigation lane carries, so the two launch paths cannot drift apart."""
    inv, lane = _both_argvs(tmp_path)
    _assert_one_ulimit(lane, "fsize", FSIZE, "lane box")
    assert _ulimits(lane, "fsize") == _ulimits(inv, "fsize"), (
        "the two launch paths render different file-size limits"
    )


@pytest.mark.parametrize("with_tenant", [True, False], ids=["tenant-agent", "no-tenant-agent"])
def test_the_investigation_box_launches_with_core_dumps_off(with_tenant, tmp_path):
    """Core dumps off, investigation lane: the default investigation box's `docker run`
    carries `--ulimit core=0:0` — once, before the image — beside its fsize cap, so a writer
    the cap kills with SIGXFSZ leaves no core file in the run dir."""
    rec = AliasProbeDocker()
    agent = _tenant_agent(tmp_path) if with_tenant else None
    _start_investigation(_run_dir(tmp_path), rec, tenant_agent=agent)
    argv = _create_argv(rec)
    _assert_one_ulimit(argv, "core", CORE_OFF, "investigation lane")
    _assert_one_ulimit(argv, "fsize", FSIZE, "investigation lane")


def test_a_lane_box_launches_with_core_dumps_off(tmp_path):
    """Core dumps off, lane boxes: a `BoxRequest` on the default spec carries
    `--ulimit core=0:0` once, before the image, so a drain lane's writable tree takes no core
    either — the same value the investigation lane carries."""
    inv, lane = _both_argvs(tmp_path)
    _assert_one_ulimit(lane, "core", CORE_OFF, "lane box")
    _assert_one_ulimit(lane, "fsize", FSIZE, "lane box")
    assert _ulimits(lane, "core") == _ulimits(inv, "core"), (
        "the two launch paths render different core limits"
    )


def test_the_box_spec_has_no_knob_for_the_file_size_cap():
    """No knob: the cap is always `READ_LIMIT`, so `BoxSpec` takes no keyword that sets it.
    The field the cap was rendered from is refused (`BoxSpec` forbids unknown keywords), and no
    field is named for a file size. Both are NAME checks: a knob brought back under an
    unrelated name would pass them."""
    with pytest.raises(ValidationError, match="file_size_limit"):
        box_mod.BoxSpec(file_size_limit=L)
    names = [f.name for f in dataclasses.fields(box_mod.BoxSpec)]
    assert not [n for n in names if "fsize" in n or "file_size" in n], (
        f"BoxSpec names a file-size field: {names}"
    )


#: Run in a FRESH interpreter: the read cap is moved before the box package is first imported,
#: then both argvs are rendered. A second literal anywhere on the way renders the old value.
_FOLLOWS_THE_READ_CAP = r"""
import json
from pathlib import Path
import defender._io as io
io.READ_LIMIT = 5_000_011
from defender.runtime import box
spec = box.BoxSpec(rootfs="stock:pinned")
run = Path("/nonexistent/runs/run-1188")
inv = box._create_argv("defender-run-1188", run, Path("/nonexistent/defender"), spec).argv
lane = box._render_argv(box.BoxRequest(name="r-1188", workdir=run, spec=spec)).argv
def fsize(argv):
    return [argv[i + 1] for i, t in enumerate(argv)
            if t == "--ulimit" and argv[i + 1].startswith("fsize=")]
print(json.dumps({"inv": fsize(inv), "lane": fsize(lane)}))
"""


def test_the_box_limit_follows_the_read_cap_rather_than_restating_it():
    """M1: L is DERIVED from `_io.READ_LIMIT` in code, not a second literal, so the two caps
    cannot drift. Observed by moving the read cap in a fresh interpreter before the box package
    loads: both rendered argvs move with it."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", _FOLLOWS_THE_READ_CAP], capture_output=True, text=True,
        encoding="utf-8", timeout=120, cwd=REPO_ROOT, env=env,
    )
    assert proc.returncode == 0, f"the probe interpreter failed: {proc.stderr}"
    seen = json.loads(proc.stdout.strip().splitlines()[-1])
    assert seen == {
        "inv": ["fsize=5000011:5000011"],
        "lane": ["fsize=5000011:5000011"],
    }, f"the box limit did not follow a moved read cap: {seen}"


# ---- live boxes: the cap enforced, through the exec path, under both runtimes ---------------

_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
_DOOD_ANCHOR = dood_anchor() if _DOOD else None

#: The predicates of #771's `requires_real_box` minus its env-levered runtime check: these
#: tests choose their runtime per case and skip a runtime the daemon does not register.
requires_box_daemon = pytest.mark.skipif(
    _NO_DAEMON or (_DOOD and _DOOD_ANCHOR is None),
    reason=(
        "no reachable Docker daemon" if _NO_DAEMON else
        "docker-outside-of-Docker with no shared mount covering the repo tree, so no bind "
        "source resolves (C46)"
    ),
)

RUNTIMES = pytest.mark.parametrize("runtime", ["runsc", "runc"])


def _need_runtime(runtime: str) -> None:
    if runtime not in docker_runtimes():
        pytest.skip(f"the {runtime!r} runtime is not registered with this daemon "
                    "(`docker info` Runtimes)")


@pytest.fixture
def base(tmp_path: Path) -> Iterator[Path]:
    """Where every live tree in a test hangs: below `tmp_path` on a native daemon, a fresh dir
    under the shared anchor under DooD. Removed afterwards on both (best-effort: the box writes
    as root). Each live test leaves files of real blocks up to the cap behind — in-cap writes
    and allocations, an over-cap writer's stub — which pytest's basetemp would otherwise keep
    for three sessions."""
    root = (
        tmp_path / "live" if _DOOD_ANCHOR is None
        else _DOOD_ANCHOR / f"t1188-{uuid.uuid4().hex}"
    )
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@dataclasses.dataclass(frozen=True)
class _Ran:
    """One command's outcome, whichever way it reached the box. A command a signal killed has
    `rc` = the negated signal number."""

    rc: int
    out: str
    err: str


@dataclasses.dataclass(frozen=True)
class _AgentExec:
    """The investigation box, reached the way the agent's commands reach it: `bash_exec.parse`,
    then `run_parsed` (a `docker exec` of the in-box runner per call). Every command runs with
    its cwd on `tree`. A bare binary the kernel kills comes back as the negated signal number
    (the runner's `Popen.returncode`)."""

    box: box_mod.BoxExecutor
    tree: Path

    def sh(self, command: str) -> _Ran:
        res = self.box.run_parsed(bash_exec.parse(command), command=command, cwd=self.tree,
                                  timeout=EXEC_TIMEOUT)
        return _Ran(res.rc, res.out.decode("utf-8", "replace"),
                    res.err.decode("utf-8", "replace"))

    def probe(self, *args: str) -> _Ran:
        # From a file on the tree: the agent's path takes a command line, not a program.
        script = self.tree / "_probe_1188.py"
        if not script.exists():
            script.write_text(_PROBE, encoding="utf-8")
        return self.sh(" ".join(["python3", str(script), *args]))


@dataclasses.dataclass(frozen=True)
class _DockerExec:
    """A lane box, reached by plain `docker exec` with its cwd on `tree`, as test_1178 drives
    one (the drain worktree has no `defender` package for the in-box runner). A command a
    signal kills exits 128 + the signal, through `sh` or bare (seen under runc: `dd` past an
    fsize limit exits 153 both ways); that is reported as `_AgentExec` reports it."""

    name: str
    tree: Path

    def _run(self, *argv: str) -> _Ran:
        done = box_mod._docker(["docker", "exec", "-w", str(self.tree), self.name, *argv])
        rc = done.returncode
        return _Ran(-(rc - 128) if rc > 128 else rc, done.stdout, done.stderr)

    def sh(self, command: str) -> _Ran:
        return self._run("sh", "-c", command)

    def probe(self, *args: str) -> _Ran:
        return self._run("python3", "-c", _PROBE, *args)


_Exec = _AgentExec | _DockerExec


@contextlib.contextmanager
def _investigation_box(base: Path, runtime: str) -> Iterator[_AgentExec]:
    """A REAL investigation box on a fresh run dir, with a tenant agent half as `run.py`
    always starts one; the run dir is the writable tree the cap must hold on."""
    run_dir = _run_dir(base)
    box = box_mod.start_box(
        run_dir, DEFENDER, spec=box_mod.BoxSpec(runtime=runtime),
        tenant_agent=_tenant_agent(base), docker=box_mod._docker,
    )
    try:
        # A startup fault under DEFENDER_ALLOW_UNSANDBOXED=1 degrades to the host executor,
        # where every negative below would be measuring the host instead of the box.
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        yield _AgentExec(box, run_dir)
    finally:
        box_mod.stop_box(box)


def _drain_worktree(base: Path) -> Path:
    """A throwaway git worktree in test_1178's shape: a committed seed under
    `defender/skills/`, then the files the box image's name is a function of copied into
    `defender/`, so the drain request resolves the image this checkout's CI built."""
    wt = init_git(base / "wt")
    write(wt / "defender" / "skills" / "seed-1188.md", "seed\n")
    commit_all(wt, "seed")
    for name in HASH_INPUTS:
        shutil.copyfile(DEFENDER / name, wt / "defender" / name)
    assert box_mod.image_tag(wt / "defender") == box_mod.image_tag(DEFENDER)
    return wt


@contextlib.contextmanager
def _lane_box(base: Path, runtime: str) -> Iterator[_DockerExec]:
    """A REAL lane box, requested the way the lead-author drain requests one
    (`drains._drain_box_request` over a throwaway worktree: the worktree read-only, its
    `skills/` read-write) with only the runtime changed. The writable tree the cap must hold on
    is read off the request, so it is the one production mounts."""
    wt = _drain_worktree(base)
    paths = LoopPaths(repo_root=wt, state_dir=base / "state")
    request = drains._drain_box_request(
        wt, f"t1188-{uuid.uuid4().hex[:8]}", LEAD_AUTHOR_DRAIN_LABEL, paths,
    )
    request = dataclasses.replace(
        request, spec=dataclasses.replace(request.spec, runtime=runtime),
    )
    writable = [Path(m.source) for m in request.mounts if m.writable]
    assert len(writable) == 1, f"the lead-author drain box mounts {writable} writable, not one"
    box = box_mod.start_box(request, docker=box_mod._docker)
    try:
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        yield _DockerExec(box.name, writable[0])
    finally:
        box_mod.stop_box(box)


#: One in-box probe, one mode per call. Every outcome is reported as DATA (exception class and
#: errno), exit 0 either way, so a probe that never ran reads differently from a refusal.
#: Python ignores SIGXFSZ, so a write past the cap surfaces as OSError(EFBIG).
_PROBE = r'''
import json, os, resource, subprocess, sys

mode, path, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
FSIZE = resource.RLIMIT_FSIZE
INF = resource.RLIM_INFINITY
BLOCK = bytes(range(256)) * 256


def outcome(fn):
    try:
        fn()
        return "ok"
    except (OSError, ValueError) as e:
        return "%s:%s" % (type(e).__name__, getattr(e, "errno", None))


out = {}
if mode == "getrlimit":
    out["fsize"] = list(resource.getrlimit(FSIZE))
    out["core"] = list(resource.getrlimit(resource.RLIMIT_CORE))
elif mode in ("ftruncate", "posix_fallocate"):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    if mode == "ftruncate":
        out[mode] = outcome(lambda: os.ftruncate(fd, n))
    else:
        out[mode] = outcome(lambda: os.posix_fallocate(fd, 0, n))
    os.close(fd)
elif mode == "write":
    # Streamed from one 64 KiB pattern block, so a write past the cap holds no more memory
    # than one under it; the offset into the block survives a short write.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    written, err = 0, None
    try:
        while written < n:
            at = written % len(BLOCK)
            written += os.write(fd, BLOCK[at:at + min(len(BLOCK) - at, n - written)])
    except OSError as e:
        err = e.errno
    os.close(fd)
    out["written"], out["errno"] = written, err
elif mode == "lift":
    hard = resource.getrlimit(FSIZE)[1]
    out["before"] = list(resource.getrlimit(FSIZE))
    # The shell first, so it meets the limit the box gave it rather than one this process
    # moved; each attempt is then independent of the ones before it.
    out["sh_hard_unlimited"] = subprocess.run(
        ["sh", "-c", "ulimit -H -f unlimited"], capture_output=True).returncode
    out["unlimited"] = outcome(lambda: resource.setrlimit(FSIZE, (INF, INF)))
    out["hard_plus_one"] = outcome(lambda: resource.setrlimit(FSIZE, (n, n + 1)))
    out["after"] = list(resource.getrlimit(FSIZE))
    # The controls: LOWERING is always allowed, in a shell and in Python, so a refusal above is
    # the hard-limit rule rather than setrlimit being unreachable.
    out["sh_lower_soft"] = subprocess.run(
        ["sh", "-c", "ulimit -S -f 1"], capture_output=True).returncode
    out["lower_soft"] = outcome(lambda: resource.setrlimit(FSIZE, (n // 2, hard)))
    out["lowered"] = list(resource.getrlimit(FSIZE))
print(json.dumps(out))
'''


def _probe(x: _Exec, mode: str, target: Path, n: int) -> dict:
    res = x.probe(mode, str(target), str(n))
    assert res.rc == 0, (
        f"the {mode} probe did not run to completion in the box (rc={res.rc}): "
        f"{res.err!r} — a broken probe, not a refusal"
    )
    return json.loads(res.out.strip().splitlines()[-1])


def _host_size(path: Path) -> int:
    """The APPARENT size the host sees (lstat, so a link is not followed); an absent file is a
    file of size 0, which is within any limit."""
    try:
        return os.lstat(path).st_size
    except FileNotFoundError:
        return 0


def _assert_rlimit_is_the_cap(x: _Exec) -> None:
    """O2: the limit every exec'd process holds, read where it applies — `getrlimit` inside the
    box, in bytes, soft and hard both equal to the read cap."""
    seen = _probe(x, "getrlimit", x.tree / "unused", 0)
    assert seen["fsize"] == [L, L], (
        f"RLIMIT_FSIZE inside the box is {seen['fsize']}, expected [{L}, {L}]"
    )


def _assert_host_takes_a_sparse_tib(tree: Path) -> None:
    """The host-side control: the same filesystem DOES take a 1 TiB sparse file outside the
    box, so a refusal inside it is the box's limit and not the filesystem's own ceiling."""
    probe = tree / f"host-sparse-{uuid.uuid4().hex[:8]}"
    try:
        with probe.open("wb") as fh:
            fh.truncate(ONE_TIB)
        assert os.lstat(probe).st_size == ONE_TIB, "the host could not size a sparse file"
    finally:
        probe.unlink(missing_ok=True)


def _assert_sparse_extension_is_bounded(x: _Exec) -> None:
    """O1/O2: a sparse extension past the cap — by the `truncate` binary and by Python's
    `os.ftruncate`, both started in the box — is refused, and the host sees no file on the
    writable tree whose apparent size exceeds the cap. Each refusal is paired with the same
    primitive, same directory, extending to UNDER the cap, which succeeds."""
    tree = x.tree
    _assert_host_takes_a_sparse_tib(tree)

    big, small = tree / "sparse-big", tree / "sparse-small"
    refused = x.sh(f"truncate -s 1T {big}")
    assert refused.rc != 0, "`truncate -s 1T` succeeded inside the box"
    assert _host_size(big) <= L, (
        f"the host sees a {_host_size(big)}-byte file the box truncated to 1 TiB (cap {L})"
    )
    allowed = x.sh(f"truncate -s {L // 2} {small}")
    assert allowed.rc == 0, (
        f"control: `truncate` under the cap failed (rc={allowed.rc}): {allowed.err!r}"
    )
    assert _host_size(small) == L // 2, "control: the in-cap truncate did not land"

    big_fd, small_fd = tree / "ftruncate-big", tree / "ftruncate-small"
    over = _probe(x, "ftruncate", big_fd, ONE_TIB)
    assert over["ftruncate"] == f"OSError:{errno.EFBIG}", (
        f"os.ftruncate(fd, 1 << 40) in the box: {over['ftruncate']} (expected EFBIG)"
    )
    assert _host_size(big_fd) <= L, f"the host sees {_host_size(big_fd)} bytes"
    under = _probe(x, "ftruncate", small_fd, L // 2)
    assert under["ftruncate"] == "ok", f"control: in-cap ftruncate refused: {under}"
    assert _host_size(small_fd) == L // 2, "control: the in-cap ftruncate did not land"


def _assert_host_takes_an_allocation_past_the_cap(tree: Path) -> None:
    """The host-side control for allocation: outside the box, the same filesystem allocates a
    file `PAST` the cap, so a refusal inside it is the box's limit — not a filesystem that
    cannot fallocate, nor one too full to."""
    probe = tree / f"host-alloc-{uuid.uuid4().hex[:8]}"
    fd = os.open(probe, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        os.posix_fallocate(fd, 0, PAST)
        assert os.fstat(fd).st_size == PAST, "the host could not allocate past the cap"
    finally:
        os.close(fd)
        probe.unlink(missing_ok=True)


def _assert_allocation_is_bounded(x: _Exec) -> None:
    """O1/O2: an ALLOCATION past the cap — the `fallocate` binary and Python's
    `os.posix_fallocate` (glibc's, which falls back to writing where the filesystem cannot
    allocate), both started in the box — is refused, and the host sees no file over the
    cap. Each primitive is tried a MiB past the cap first and at 1 TiB only once that was
    refused: an allocation that is NOT refused really takes the blocks. Control for each: the
    same primitive, same directory, allocating half the cap, lands at exactly that size."""
    tree = x.tree
    _assert_host_takes_an_allocation_past_the_cap(tree)

    for size, name in ((PAST, "fallocate-past"), (ONE_TIB, "fallocate-tib")):
        refused = x.sh(f"fallocate -l {size} {tree / name}")
        assert refused.rc != 127, f"there is no `fallocate` in the box image: {refused.err!r}"
        assert refused.rc != 0, f"`fallocate -l {size}` succeeded inside the box"
        assert _host_size(tree / name) <= L, (
            f"the host sees a {_host_size(tree / name)}-byte file the box allocated (cap {L})"
        )
    small = tree / "fallocate-small"
    allowed = x.sh(f"fallocate -l {L // 2} {small}")
    assert allowed.rc == 0, (
        f"control: `fallocate` under the cap failed (rc={allowed.rc}): {allowed.err!r}"
    )
    assert _host_size(small) == L // 2, "control: the in-cap fallocate did not land"

    for size, name in ((PAST, "posix-fallocate-past"), (ONE_TIB, "posix-fallocate-tib")):
        over = _probe(x, "posix_fallocate", tree / name, size)
        assert over["posix_fallocate"] == f"OSError:{errno.EFBIG}", (
            f"os.posix_fallocate(fd, 0, {size}) in the box: {over['posix_fallocate']} "
            "(expected EFBIG)"
        )
        assert _host_size(tree / name) <= L, f"the host sees {_host_size(tree / name)} bytes"
    small = tree / "posix-fallocate-small"
    under = _probe(x, "posix_fallocate", small, L // 2)
    assert under["posix_fallocate"] == "ok", f"control: in-cap posix_fallocate refused: {under}"
    assert _host_size(small) == L // 2, "control: the in-cap posix_fallocate did not land"


#: The probe's write pattern, restated host-side: the probe writes it from the start of the
#: file again at every `len(BLOCK)` boundary, so byte i of what it wrote is `BLOCK[i % 65536]`.
BLOCK = bytes(range(256)) * 256


def _assert_holds_the_pattern(path: Path, size: int) -> None:
    """`path` is exactly `size` bytes of the probe's pattern — read one block at a time, so the
    check holds no more memory for a file at the cap than for an empty one."""
    seen = 0
    with path.open("rb") as fh:
        while chunk := fh.read(len(BLOCK)):
            assert chunk == BLOCK[:len(chunk)], (
                f"control: the in-cap write did not land byte for byte (block at {seen})"
            )
            seen += len(chunk)
    assert seen == size, f"control: the in-cap write landed {seen} bytes, not {size}"


def _assert_real_write_stops_at_the_cap(x: _Exec) -> None:
    """O1/O2: a REAL write past the cap — data, not a hole — onto the writable tree (never
    `/tmp`, whose 64m tmpfs would answer ENOSPC first) stops: EFBIG in the box, and the host
    sees at most `L` bytes. Control on the same tree: a write under the cap lands with exactly
    the bytes written."""
    past = x.tree / "write-past"
    over = _probe(x, "write", past, PAST)
    assert over["errno"] == errno.EFBIG, f"a write past the cap was not refused: {over}"
    assert over["written"] <= L, f"the box wrote {over['written']} bytes (cap {L})"
    assert _host_size(past) <= L, f"the host sees {_host_size(past)} bytes (cap {L})"

    within = x.tree / "write-within"
    under = _probe(x, "write", within, L // 2)
    assert under == {"written": L // 2, "errno": None}, f"control: {under}"
    _assert_holds_the_pattern(within, L // 2)


def _assert_the_box_cannot_lift_it(x: _Exec) -> None:
    """O3 (M2): a process in the box cannot raise the limit — not to unlimited, not by one byte
    of hard limit, not through the shell's `ulimit -H -f unlimited` — and the limit it holds
    afterwards is unchanged. Control in the same process: lowering it succeeds."""
    seen = _probe(x, "lift", x.tree / "unused", L)
    assert seen["before"] == [L, L], f"the box did not start at the cap: {seen}"
    assert seen["unlimited"] != "ok", "setrlimit(RLIMIT_FSIZE, unlimited) succeeded in the box"
    assert seen["hard_plus_one"] != "ok", "the box raised its hard file-size limit past L"
    assert seen["sh_hard_unlimited"] != 0, "`ulimit -H -f unlimited` succeeded in the box"
    assert seen["after"] == [L, L], f"the limit moved after the attempts: {seen}"
    assert seen["sh_lower_soft"] == 0, f"control: the shell could not even lower it: {seen}"
    assert seen["lower_soft"] == "ok", f"control: setrlimit is unreachable, not refused: {seen}"
    assert seen["lowered"] == [L // 2, L], f"control: lowering did not take: {seen}"


def _assert_the_box_cannot_make_a_file_past_the_cap(x: _Exec) -> None:
    _assert_rlimit_is_the_cap(x)
    _assert_sparse_extension_is_bounded(x)
    _assert_allocation_is_bounded(x)
    _assert_real_write_stops_at_the_cap(x)
    _assert_the_box_cannot_lift_it(x)


def _assert_a_writer_the_cap_kills_leaves_no_core(x: _Exec) -> None:
    """A writer that does NOT ignore SIGXFSZ (`dd`, a bare binary) writes past the cap with its
    cwd on the writable tree and is killed by the signal — the positive control that a dump
    was due — and the file it was writing stops at the cap.

    The `core*` scan after it CANNOT FAIL on most hosts, with or without `core=0:0`: a pipe
    `kernel.core_pattern` (apport, systemd-coredump — the dev box's and Ubuntu runners') hands
    the core to a host helper, an absolute-path pattern (`/var/crash/core.%p`) writes it
    outside the tree, and gVisor (runsc) writes no host core at all. It can fail only under
    runc on a host whose pattern is a relative path. The check that fails without the flag is
    `RLIMIT_CORE == (0, 0)`, in `_assert_core_dumps_are_off`."""
    writer = "xfsz-writer"    # relative: the core, if any, would land beside it
    killed = x.sh(f"dd if=/dev/zero of={writer} bs=1M count={PAST >> 20}")
    assert killed.rc == -signal.SIGXFSZ, (
        f"control: the over-cap writer was not killed by SIGXFSZ (rc={killed.rc}): "
        f"{killed.err!r}"
    )
    assert _host_size(x.tree / writer) <= L, (
        f"the host sees {_host_size(x.tree / writer)} bytes"
    )
    cores = sorted(str(p.relative_to(x.tree)) for p in x.tree.rglob("core*"))
    assert cores == [], f"a writer the cap killed left core file(s) on the writable tree: {cores}"


def _assert_core_dumps_are_off(x: _Exec) -> None:
    """Every exec'd process holds RLIMIT_CORE = (0, 0): no core, and a hard limit of 0 leaves
    the soft one nowhere to rise (raising the hard one needs CAP_SYS_RESOURCE, which O3's
    lift attempts show the box lacks)."""
    seen = _probe(x, "getrlimit", x.tree / "unused", 0)
    assert seen["core"] == [0, 0], (
        f"RLIMIT_CORE inside the box is {seen['core']}, expected [0, 0]"
    )


@requires_box_daemon
@RUNTIMES
def test_a_live_investigation_box_cannot_make_a_file_past_the_read_cap(runtime, base):
    """O1/O2/O3, investigation lane, under each runtime: the box an investigation actually
    gets holds RLIMIT_FSIZE = READ_LIMIT, soft and hard, in every exec'd process; on the
    run-dir bind a sparse extension (`truncate -s 1T`, `ftruncate`), an allocation
    (`fallocate`, `posix_fallocate`) and a real write past it are each refused with the host
    seeing nothing over the cap, while the same primitive under it lands; and nothing in the
    box can raise it. Commands go through `run_parsed`, as the agent's do."""
    _need_runtime(runtime)
    with _investigation_box(base, runtime) as x:
        _assert_the_box_cannot_make_a_file_past_the_cap(x)


@requires_box_daemon
@RUNTIMES
def test_a_live_lane_box_cannot_make_a_file_past_the_read_cap(runtime, base):
    """O1/O2/O3, lane path, under each runtime: a box requested as the lead-author drain
    requests one holds the same cap, with the same refusals and the same controls, on the
    `skills/` tree it mounts read-write."""
    _need_runtime(runtime)
    with _lane_box(base, runtime) as x:
        _assert_the_box_cannot_make_a_file_past_the_cap(x)


@requires_box_daemon
@RUNTIMES
def test_a_live_investigation_box_dumps_no_core(runtime, base):
    """Core dumps off, investigation lane, under each runtime: every exec'd process holds
    RLIMIT_CORE = (0, 0), and a writer the cap kills leaves no core in the run dir."""
    _need_runtime(runtime)
    with _investigation_box(base, runtime) as x:
        _assert_a_writer_the_cap_kills_leaves_no_core(x)
        _assert_core_dumps_are_off(x)


@requires_box_daemon
@RUNTIMES
def test_a_live_lane_box_dumps_no_core(runtime, base):
    """Core dumps off, lane path, under each runtime: the same on the drain box's writable
    `skills/` tree."""
    _need_runtime(runtime)
    with _lane_box(base, runtime) as x:
        _assert_a_writer_the_cap_kills_leaves_no_core(x)
        _assert_core_dumps_are_off(x)
