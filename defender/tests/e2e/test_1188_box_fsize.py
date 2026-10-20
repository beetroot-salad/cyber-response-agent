"""#1188 e2e: the box file-size cap. Both box launch argvs carry --ulimit fsize=READ_LIMIT (investigation box and lane box), and on a live box (runsc and runc) no process can make a file past the cap, sparse, allocated or written, nor lift the limit."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import dataclasses
import errno
import json
import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender._io import READ_LIMIT
from defender.tenancy._tenant import TenantId, tenant_id_file_text
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.execution import bash_exec
from defender import box as box_mod
from defender.box._image import HASH_INPUTS
from defender.tests.support.runtime.state._1255_view import MODEL_RUN
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.runtime.engine._declared869 import commit_all, init_git
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.learning.curation._lead_author_1134 import write
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

ONE_TIB = 1 << 40

EXEC_TIMEOUT = 60.0


# ---- argv readers --------------------------------------------------------------------------

def _create_argv(rec: AliasProbeDocker) -> list[str]:
    assert rec.create_argv is not None, "start_box never issued `docker run`"
    return rec.create_argv


def _ulimits(argv: list[str], resource: str) -> list[str]:
    """Every `--ulimit <resource>=…` value on a captured create argv, in order."""
    return [
        argv[i + 1] for i, tok in enumerate(argv)
        if tok == "--ulimit" and i + 1 < len(argv) and argv[i + 1].startswith(f"{resource}=")
    ]


def _assert_one_ulimit(argv: list[str], resource: str, want: str, lane: str) -> None:
    """Exactly one `<resource>` ulimit, equal to `want`, and in OPTION position:"""
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
    """A run dir whose NAME is unique:"""
    run = base / f"run-1188-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True)
    plant_alert(run, {"id": "a-1188"})
    return run


def _start_investigation(
    run_dir: Path, rec: AliasProbeDocker, *, tenant_agent: Path | None = None,
) -> None:
    """No `spec=`: the env-resolved default every investigation gets."""
    box_mod.start_box(run_dir, DEFENDER, tenant_agent=tenant_agent, docker=rec)


def _tenant_agent(base: Path) -> Path:
    """A tenant's agent half, as `run.py` always passes one:"""
    agent = base / f"tenant-agent-{uuid.uuid4().hex[:8]}"
    agent.mkdir(parents=True)
    (agent / ".tenant-id").write_text(tenant_id_file_text(TenantId(fixture_uuid("tenant:fsize-test"))), encoding="utf-8")
    return agent


def _start_lane(tmp_path: Path, rec: AliasProbeDocker, spec) -> None:
    """The lane path in #771's `_request` shape:"""
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
    """The investigation box's and a lane box's create argvs, each on the env-resolved default spec (what..."""
    inv = AliasProbeDocker()
    _start_investigation(_run_dir(tmp_path), inv, tenant_agent=_tenant_agent(tmp_path))
    lane = AliasProbeDocker()
    _start_lane(tmp_path, lane, _stock(box_mod.BoxSpec.from_env(os.environ)))
    return _create_argv(inv), _create_argv(lane)


@pytest.mark.parametrize("with_tenant", [True, False], ids=["tenant-agent", "no-tenant-agent"])
def test_the_investigation_box_launches_with_the_read_cap_as_its_file_size_limit(
    with_tenant, tmp_path,
):
    """O1/O2 (M1), investigation lane:"""
    rec = AliasProbeDocker()
    agent = _tenant_agent(tmp_path) if with_tenant else None
    _start_investigation(_run_dir(tmp_path), rec, tenant_agent=agent)
    argv = _create_argv(rec)
    _assert_one_ulimit(argv, "fsize", FSIZE, "investigation lane")
    _assert_one_ulimit(argv, "core", CORE_OFF, "investigation lane")


def test_a_lane_box_launches_with_the_read_cap_as_its_file_size_limit(tmp_path):
    """A lane box carries the same fsize cap as the investigation box."""
    inv, lane = _both_argvs(tmp_path)
    _assert_one_ulimit(lane, "fsize", FSIZE, "lane box")
    _assert_one_ulimit(lane, "core", CORE_OFF, "lane box")
    assert _ulimits(lane, "fsize") == _ulimits(inv, "fsize"), (
        "the two launch paths render different file-size limits"
    )


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
    """Where every live tree in a test hangs:"""
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
    """One command's outcome, whichever way it reached the box."""

    rc: int
    out: str
    err: str


@dataclasses.dataclass(frozen=True)
class _AgentExec:
    """The investigation box, reached the way the agent's commands reach it:"""

    box: box_mod.BoxExecutor
    tree: Path
    inside: Path = Path(MODEL_RUN)

    def at(self, host: Path) -> str:
        """`host`, a path under `tree`, as a command in the box names it."""
        return str(self.inside / host.relative_to(self.tree))

    def sh(self, command: str) -> _Ran:
        res = self.box.run_parsed(bash_exec.parse(command), command=command, cwd=self.inside,
                                  timeout=EXEC_TIMEOUT)
        return _Ran(res.rc, res.out.decode("utf-8", "replace"),
                    res.err.decode("utf-8", "replace"))

    def probe(self, *args: str) -> _Ran:
        # From a file on the tree: the agent's path takes a command line, not a program.
        script = self.tree / "_probe_1188.py"
        if not script.exists():
            script.write_text(_PROBE, encoding="utf-8")
        return self.sh(" ".join(["python3", self.at(script), *args]))


@dataclasses.dataclass(frozen=True)
class _DockerExec:
    """A lane box, reached by plain `docker exec` with its cwd on `tree`, as test_1178 drives one (the drain..."""

    name: str
    tree: Path
    inside: Path

    def at(self, host: Path) -> str:
        """`host`, a path under `tree`, as a command in the box names it."""
        return str(self.inside / host.relative_to(self.tree))

    def _run(self, *argv: str) -> _Ran:
        done = box_mod._docker(["docker", "exec", "-w", str(self.inside), self.name, *argv])
        rc = done.returncode
        return _Ran(-(rc - 128) if rc > 128 else rc, done.stdout, done.stderr)

    def sh(self, command: str) -> _Ran:
        return self._run("sh", "-c", command)

    def probe(self, *args: str) -> _Ran:
        return self._run("python3", "-c", _PROBE, *args)


_Exec = _AgentExec | _DockerExec


@contextlib.contextmanager
def _investigation_box(base: Path, runtime: str) -> Iterator[_AgentExec]:
    """A REAL investigation box on a fresh run dir, with a tenant agent half as `run.py` always starts one;"""
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
    `defender/`, so the drain request resolves the image this checkout's CI built, and the
    product's code check file its read-only `code` mount is read back at (#1108 D7 amended)."""
    wt = init_git(base / "wt")
    write(wt / "defender" / "skills" / "seed-1188.md", "seed\n")
    commit_all(wt, "seed")
    for name in (*HASH_INPUTS, box_mod.CODE_CHECK_FILE):
        shutil.copyfile(DEFENDER / name, wt / "defender" / name)
    assert box_mod.image_tag(wt / "defender") == box_mod.image_tag(DEFENDER)
    return wt


@contextlib.contextmanager
def _lane_box(base: Path, runtime: str) -> Iterator[_DockerExec]:
    """A REAL lane box, requested the way the lead-author drain requests one (`drains._drain_box_request` over a..."""
    wt = _drain_worktree(base)
    paths = LoopPaths(repo_root=wt, state_dir=base / "state")
    request = drains._drain_box_request(
        wt, f"t1188-{uuid.uuid4().hex[:8]}", LEAD_AUTHOR_DRAIN_LABEL, paths,
    )
    request = dataclasses.replace(
        request, spec=dataclasses.replace(request.spec, runtime=runtime),
    )
    writable = [m for m in request.mounts if m.writable]
    assert len(writable) == 1, f"the lead-author drain box mounts {writable} writable, not one"
    box = box_mod.start_box(request, docker=box_mod._docker)
    try:
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        yield _DockerExec(box.name, Path(writable[0].source), Path(writable[0].target))
    finally:
        box_mod.stop_box(box)


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
    """Run the probe in the box on `target`, a host path under `x.tree`, named as the box
    names it."""
    res = x.probe(mode, x.at(target), str(n))
    assert res.rc == 0, (
        f"the {mode} probe did not run to completion in the box (rc={res.rc}): "
        f"{res.err!r} — a broken probe, not a refusal"
    )
    return json.loads(res.out.strip().splitlines()[-1])


def _host_size(path: Path) -> int:
    """The APPARENT size the host sees (lstat, so a link is not followed);"""
    try:
        return os.lstat(path).st_size
    except FileNotFoundError:
        return 0


def _assert_rlimit_is_the_cap(x: _Exec) -> None:
    """O2:"""
    seen = _probe(x, "getrlimit", x.tree / "unused", 0)
    assert seen["fsize"] == [L, L], (
        f"RLIMIT_FSIZE inside the box is {seen['fsize']}, expected [{L}, {L}]"
    )


def _assert_host_takes_a_sparse_tib(tree: Path) -> None:
    """The host-side control:"""
    probe = tree / f"host-sparse-{uuid.uuid4().hex[:8]}"
    try:
        with probe.open("wb") as fh:
            fh.truncate(ONE_TIB)
        assert os.lstat(probe).st_size == ONE_TIB, "the host could not size a sparse file"
    finally:
        probe.unlink(missing_ok=True)


def _assert_sparse_extension_is_bounded(x: _Exec) -> None:
    """O1/O2:"""
    tree = x.tree
    _assert_host_takes_a_sparse_tib(tree)

    big, small = tree / "sparse-big", tree / "sparse-small"
    refused = x.sh(f"truncate -s 1T {x.at(big)}")
    assert refused.rc != 0, "`truncate -s 1T` succeeded inside the box"
    assert _host_size(big) <= L, (
        f"the host sees a {_host_size(big)}-byte file the box truncated to 1 TiB (cap {L})"
    )
    allowed = x.sh(f"truncate -s {L // 2} {x.at(small)}")
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
    """The host-side control for allocation:"""
    probe = tree / f"host-alloc-{uuid.uuid4().hex[:8]}"
    fd = os.open(probe, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        os.posix_fallocate(fd, 0, PAST)
        assert os.fstat(fd).st_size == PAST, "the host could not allocate past the cap"
    finally:
        os.close(fd)
        probe.unlink(missing_ok=True)


def _assert_allocation_is_bounded(x: _Exec) -> None:
    """O1/O2:"""
    tree = x.tree
    _assert_host_takes_an_allocation_past_the_cap(tree)

    for size, name in ((PAST, "fallocate-past"), (ONE_TIB, "fallocate-tib")):
        refused = x.sh(f"fallocate -l {size} {x.at(tree / name)}")
        assert refused.rc != 127, f"there is no `fallocate` in the box image: {refused.err!r}"
        assert refused.rc != 0, f"`fallocate -l {size}` succeeded inside the box"
        assert _host_size(tree / name) <= L, (
            f"the host sees a {_host_size(tree / name)}-byte file the box allocated (cap {L})"
        )
    small = tree / "fallocate-small"
    allowed = x.sh(f"fallocate -l {L // 2} {x.at(small)}")
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
    """`path` is exactly `size` bytes of the probe's pattern — read one block at a time, so the check holds no..."""
    seen = 0
    with path.open("rb") as fh:
        while chunk := fh.read(len(BLOCK)):
            assert chunk == BLOCK[:len(chunk)], (
                f"control: the in-cap write did not land byte for byte (block at {seen})"
            )
            seen += len(chunk)
    assert seen == size, f"control: the in-cap write landed {seen} bytes, not {size}"


def _assert_real_write_stops_at_the_cap(x: _Exec) -> None:
    """O1/O2:"""
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
    """O3 (M2):"""
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


@requires_box_daemon
@RUNTIMES
def test_a_live_investigation_box_cannot_make_a_file_past_the_read_cap(runtime, base):
    """O1/O2/O3, investigation lane, under each runtime:"""
    _need_runtime(runtime)
    with _investigation_box(base, runtime) as x:
        _assert_the_box_cannot_make_a_file_past_the_cap(x)


@requires_box_daemon
@RUNTIMES
def test_a_live_lane_box_cannot_make_a_file_past_the_read_cap(runtime, base):
    """O1/O2/O3, lane path, under each runtime:"""
    _need_runtime(runtime)
    with _lane_box(base, runtime) as x:
        _assert_the_box_cannot_make_a_file_past_the_cap(x)
