"""#1188 — the box file-size limit: M1 (`--ulimit fsize=L:L` on both box `docker run` argvs),
M2 (the box cannot lift it) and M3 (proved on a live box, under both runtimes, through the exec
path the agent's commands take).

The obligations, from the design comment on #1188:

* O1 — no file a box writes on a writable mount can exceed the host's whole-file read cap
  (`_io.READ_LIMIT`). Apparent size is what counts, so a sparse file is no exception.
* O2 — O1 holds on BOTH launch paths (the investigation box, `_create_argv`; the lane boxes,
  `_render_argv` via `BoxRequest`) and for every process in the box, including the commands
  `docker exec` brings in (`BoxExecutor.run_parsed`).
* O3 — the box cannot lift the limit (`ulimit -Hf unlimited` inside it fails).

The interface pinned here: `BoxSpec` gains `file_size_limit: int` — bytes, defaulting to
`defender._io.READ_LIMIT`, the value's single owner — and both argvs carry
`--ulimit fsize=<L>:<L>` (soft = hard = L, in bytes: Docker's unit, C3) with L the
spec's `file_size_limit`.

RED AT `6443b33b`, and for two different reasons:

* No argv carries `--ulimit` yet, so the argv tests fail on the missing flag, and a live box
  started with the default spec is unbounded: the default-limit live tests fail on
  `RLIMIT_FSIZE` reading `[-1, -1]` (unlimited) inside the box. Run one at a time against such
  a box, every negative below fails on its own too — `truncate -s 1T` exits 0, `ftruncate`
  returns, a 2 MiB write lands whole, `ulimit -H -f unlimited` and `setrlimit` succeed — which
  was checked by hand under runc before this suite was committed.
* `BoxSpec` is a strict model with `extra="forbid"`, so `BoxSpec(file_size_limit=...)` raises
  pydantic's `ValidationError` naming the field. Every test that sets a non-default limit is
  red on THAT until the field lands; the default-limit live tests above are what show the box
  itself is unbounded today.

Every `file_size_limit` reference sits inside a test body, so the module collects at HEAD and
each test fails on its own account.

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
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender._io import READ_LIMIT
from defender.runtime import bash_exec, box as box_mod
from defender.tests._docker import daemon_reachable, is_dood
from defender.tests.e2e._spec771 import AliasProbeDocker

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent

#: Docker's `--ulimit` unit for fsize is bytes (C3: `fsize=1048576` stopped `dd` at exactly
#: 1048576 bytes), so this is the value both argvs must carry by default.
DEFAULT_FSIZE = f"fsize={READ_LIMIT}:{READ_LIMIT}"

#: The small limit the live tests set, so a real write past it costs a megabyte rather than
#: the 64 MiB default. Not smaller: bash_exec's own stderr spool lives under the same limit.
SMALL_LIMIT = 1 << 20

#: Far past any limit, and cheap: a sparse extension writes no data blocks.
ONE_TIB = 1 << 40

EXEC_TIMEOUT = 60.0


# ---- argv readers --------------------------------------------------------------------------

def _create_argv(rec: AliasProbeDocker) -> list[str]:
    assert rec.create_argv is not None, "start_box never issued `docker run`"
    return rec.create_argv


def _fsize_ulimits(argv: list[str]) -> list[str]:
    """Every `--ulimit fsize=…` value on a captured create argv, in order. All of them, not the
    first `--ulimit`: a second flag (another resource, or a second fsize) must not hide the one
    the test is about."""
    return [
        argv[i + 1] for i, tok in enumerate(argv)
        if tok == "--ulimit" and i + 1 < len(argv) and argv[i + 1].startswith("fsize=")
    ]


def _assert_one_fsize_option(argv: list[str], want: str, lane: str) -> None:
    """Exactly one fsize ulimit, equal to `want`, and in OPTION position: `docker run` reads
    everything after the image as the container's command, so a flag appended after the image
    would be an argument to `sleep`, not a limit."""
    got = _fsize_ulimits(argv)
    assert got == [want], (
        f"{lane}: the create argv carries fsize ulimit(s) {got}, expected exactly [{want!r}] — "
        f"argv: {argv}"
    )
    assert argv[-2:] == ["sleep", "infinity"], f"{lane}: unexpected argv tail {argv[-3:]}"
    image_at = len(argv) - 3
    at = argv.index(want) - 1    # the `--ulimit` token `_fsize_ulimits` read the value after
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
    run_dir: Path, rec: AliasProbeDocker, spec=None, *, tenant_agent: Path | None = None,
) -> None:
    kw = {} if spec is None else {"spec": spec}
    box_mod.start_box(run_dir, DEFENDER, tenant_agent=tenant_agent, docker=rec, **kw)


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
    _assert_one_fsize_option(_create_argv(rec), DEFAULT_FSIZE, "investigation lane")


def test_a_lane_box_launches_with_the_read_cap_as_its_file_size_limit(tmp_path):
    """O1/O2 (M1), lane boxes: a `BoxRequest` on the env-resolved default spec (what
    `drains._drain_box_request` builds) issues a `docker run` carrying
    `--ulimit fsize=READ_LIMIT:READ_LIMIT`, once, before the image — and the SAME value the
    investigation lane carries, so the two launch paths cannot drift apart."""
    lane = AliasProbeDocker()
    _start_lane(tmp_path, lane, _stock(box_mod.BoxSpec.from_env(os.environ)))
    _assert_one_fsize_option(_create_argv(lane), DEFAULT_FSIZE, "lane box")

    inv = AliasProbeDocker()
    _start_investigation(_run_dir(tmp_path), inv)
    assert _fsize_ulimits(_create_argv(lane)) == _fsize_ulimits(_create_argv(inv)), (
        "the two launch paths render different file-size limits"
    )


#: Two non-default, non-round limits: an argv built from a literal, or from READ_LIMIT
#: directly instead of the spec, renders neither.
@pytest.mark.parametrize("limit", [1_048_583, 7_340_033])
def test_the_investigation_box_carries_the_limit_its_spec_names(limit, tmp_path):
    """M1, investigation lane: the limit on the argv is the run's `spec.file_size_limit`, not
    a constant — `start_box(..., spec=BoxSpec(file_size_limit=X))` renders `fsize=X:X`."""
    rec = AliasProbeDocker()
    spec = box_mod.BoxSpec(file_size_limit=limit)
    _start_investigation(_run_dir(tmp_path), rec, spec, tenant_agent=_tenant_agent(tmp_path))
    _assert_one_fsize_option(_create_argv(rec), f"fsize={limit}:{limit}", "investigation lane")


@pytest.mark.parametrize("limit", [1_048_583, 7_340_033])
def test_a_lane_box_carries_the_limit_its_request_spec_names(limit, tmp_path):
    """M1, lane boxes: the limit on the argv is the request's `spec.file_size_limit` —
    `BoxRequest(..., spec=BoxSpec(file_size_limit=X))` renders `fsize=X:X`."""
    rec = AliasProbeDocker()
    spec = box_mod.BoxSpec(rootfs="python:3.11-slim", file_size_limit=limit)
    _start_lane(tmp_path, rec, spec)
    _assert_one_fsize_option(_create_argv(rec), f"fsize={limit}:{limit}", "lane box")


def test_the_spec_default_is_the_read_cap_in_bytes():
    """The limit's single owner is `BoxSpec.file_size_limit`, and its default IS the host's
    whole-file read cap, in bytes: on the bare spec, on the env-resolved spec with no lever
    set, and on the runc-levered spec (the lever moves the runtime and nothing else)."""
    assert box_mod.BoxSpec().file_size_limit == READ_LIMIT
    assert box_mod.BoxSpec.from_env({}).file_size_limit == READ_LIMIT
    levered = box_mod.BoxSpec.from_env({box_mod.BoxSpec.ENV_VAR: "runc"})
    assert levered.runtime == "runc"
    assert levered.file_size_limit == READ_LIMIT


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
    return [argv[i + 1] for i, t in enumerate(argv) if t == "--ulimit"]
print(json.dumps({"default": spec.file_size_limit, "inv": fsize(inv), "lane": fsize(lane)}))
"""


def test_the_box_limit_follows_the_read_cap_rather_than_restating_it():
    """M1: L is DERIVED from `_io.READ_LIMIT` in code, not a second literal, so the two caps
    cannot drift. Observed by moving the read cap in a fresh interpreter before the box package
    loads: the spec's default and both rendered argvs move with it."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", _FOLLOWS_THE_READ_CAP], capture_output=True, text=True,
        encoding="utf-8", timeout=120, cwd=REPO_ROOT, env=env,
    )
    assert proc.returncode == 0, f"the probe interpreter failed: {proc.stderr}"
    seen = json.loads(proc.stdout.strip().splitlines()[-1])
    assert seen == {
        "default": 5_000_011,
        "inv": ["fsize=5000011:5000011"],
        "lane": ["fsize=5000011:5000011"],
    }, f"the box limit did not follow a moved read cap: {seen}"


# ---- live boxes: the limit enforced, through the exec path, under both runtimes -------------

def _docker_runtimes() -> frozenset[str]:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    return frozenset(probe.stdout.split()) if probe.returncode == 0 else frozenset()


_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()


def _dood_anchor() -> Path | None:
    """Under docker-outside-of-Docker a bind source must lie on a path the daemon shares, and
    `tmp_path` does not; the repo's gitignored `.defender-runs/` does when the repo is covered
    (test_540's convention). None when even the repo is uncovered: nothing here is observable."""
    mounts = box_mod._shared_mounts(box_mod._docker)
    if not mounts or not box_mod._covered(DEFENDER, mounts):
        return None
    return REPO_ROOT / ".defender-runs"


_DOOD_ANCHOR = _dood_anchor() if _DOOD else None

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
    if runtime not in _docker_runtimes():
        pytest.skip(f"the {runtime!r} runtime is not registered with this daemon "
                    "(`docker info` Runtimes)")


@pytest.fixture
def base(tmp_path: Path) -> Iterator[Path]:
    """Where every live tree in a test hangs: `tmp_path` on a native daemon, a fresh dir under
    the shared anchor under DooD (removed afterwards; the box writes as root, so best-effort)."""
    if _DOOD_ANCHOR is None:
        yield tmp_path
        return
    root = _DOOD_ANCHOR / f"t1188-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _spec(runtime: str, limit: int | None = None):
    """The live box's spec. With `limit`, the non-default field — a `ValidationError` naming
    `file_size_limit` until the field exists."""
    if limit is None:
        return box_mod.BoxSpec(runtime=runtime)
    return box_mod.BoxSpec(runtime=runtime, file_size_limit=limit)


@contextlib.contextmanager
def _investigation_box(run_dir: Path, spec) -> Iterator[object]:
    # With a tenant agent half, as `run.py` always starts one.
    agent = _tenant_agent(run_dir.parent)
    box = box_mod.start_box(
        run_dir, DEFENDER, spec=spec, tenant_agent=agent, docker=box_mod._docker,
    )
    try:
        # A startup fault under DEFENDER_ALLOW_UNSANDBOXED=1 degrades to the host executor,
        # where every negative below would be measuring the host instead of the box.
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        yield box
    finally:
        box_mod.stop_box(box)


@contextlib.contextmanager
def _lane_box(base: Path, spec) -> Iterator[tuple[object, Path]]:
    """A REAL lane box in test_665_box_live's run-cycle shape: this tree mounted read-only (so
    the exec entrypoint imports and the rootfs resolves to this tree's image through the
    production path) and one writable tree, the mount the limit must hold on."""
    tree = base / "lane-rw"
    tree.mkdir(parents=True)
    request = box_mod.BoxRequest(
        name=f"defender-drain-1188-{uuid.uuid4().hex[:8]}",
        mounts=(
            box_mod.Mount(source=DEFENDER, target=DEFENDER, writable=False),
            box_mod.Mount(source=tree, target=tree, writable=True),
        ),
        workdir=REPO_ROOT, env={}, spec=spec,
    )
    box = box_mod.start_box(request, docker=box_mod._docker)
    try:
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        yield box, tree
    finally:
        box_mod.stop_box(box)


def _exec(box, command: str, cwd: Path):
    """The REAL exec transport the agent's commands take: `bash_exec.parse`, then
    `run_parsed` (a `docker exec` per call)."""
    return box.run_parsed(bash_exec.parse(command), command=command, cwd=cwd,
                          timeout=EXEC_TIMEOUT)


#: One in-box probe, one mode per call. Every outcome is reported as DATA (exception class and
#: errno), exit 0 either way, so a probe that never ran reads differently from a refusal.
#: Python ignores SIGXFSZ, so a write past the limit surfaces as OSError(EFBIG).
_PROBE = r'''
import json, os, resource, subprocess, sys

mode, path, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
FSIZE = resource.RLIMIT_FSIZE
INF = resource.RLIM_INFINITY


def outcome(fn):
    try:
        fn()
        return "ok"
    except (OSError, ValueError) as e:
        return "%s:%s" % (type(e).__name__, getattr(e, "errno", None))


def pattern(size):
    block = bytes(range(256)) * 256
    return (block * (size // len(block) + 1))[:size]


out = {}
if mode == "getrlimit":
    out["fsize"] = list(resource.getrlimit(FSIZE))
elif mode == "ftruncate":
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    out["ftruncate"] = outcome(lambda: os.ftruncate(fd, n))
    os.close(fd)
elif mode == "write":
    data = pattern(n)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    written, err = 0, None
    try:
        while written < n:
            written += os.write(fd, data[written:written + 65536])
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


def _probe(box, tree: Path, mode: str, target: Path, n: int) -> dict:
    script = tree / "_probe_1188.py"
    if not script.exists():
        script.write_text(_PROBE, encoding="utf-8")
    command = f"python3 {script} {mode} {target} {n}"
    res = _exec(box, command, tree)
    assert res.rc == 0, (
        f"the {mode} probe did not run to completion in the box (rc={res.rc}): "
        f"{res.err.decode('utf-8', 'replace')!r} — a broken probe, not a refusal"
    )
    return json.loads(res.out.decode("utf-8", "replace").strip().splitlines()[-1])


def _host_size(path: Path) -> int:
    """The APPARENT size the host sees (lstat, so a link is not followed); an absent file is a
    file of size 0, which is within any limit."""
    try:
        return os.lstat(path).st_size
    except FileNotFoundError:
        return 0


def _assert_host_holds_a_sparse_tib(tree: Path) -> None:
    """The host-side control: the same filesystem DOES take a 1 TiB sparse file outside the
    box, so a refusal inside it is the box's limit and not the filesystem's own ceiling."""
    probe = tree / f"host-sparse-{uuid.uuid4().hex[:8]}"
    try:
        with probe.open("wb") as fh:
            fh.truncate(ONE_TIB)
        assert os.lstat(probe).st_size == ONE_TIB, "the host could not size a sparse file"
    finally:
        probe.unlink(missing_ok=True)


def _assert_sparse_extension_is_bounded(box, tree: Path, limit: int) -> None:
    """O1/O2: a sparse extension past the limit — by the `truncate` binary and by Python's
    `os.ftruncate`, both started through the exec path — is refused, and the host sees no file
    on the writable tree whose apparent size exceeds the limit. Each refusal is paired with
    the same primitive, same directory, extending to UNDER the limit, which succeeds."""
    _assert_host_holds_a_sparse_tib(tree)

    big, small = tree / "sparse-big", tree / "sparse-small"
    refused = _exec(box, f"truncate -s 1T {big}", tree)
    assert refused.rc != 0, "`truncate -s 1T` succeeded inside the box"
    assert _host_size(big) <= limit, (
        f"the host sees a {_host_size(big)}-byte file the box truncated to 1 TiB (limit {limit})"
    )
    allowed = _exec(box, f"truncate -s {limit // 2} {small}", tree)
    assert allowed.rc == 0, (
        f"control: `truncate` under the limit failed (rc={allowed.rc}): {allowed.err!r}"
    )
    assert _host_size(small) == limit // 2, "control: the in-limit truncate did not land"

    big_fd, small_fd = tree / "ftruncate-big", tree / "ftruncate-small"
    over = _probe(box, tree, "ftruncate", big_fd, ONE_TIB)
    assert over["ftruncate"] == f"OSError:{errno.EFBIG}", (
        f"os.ftruncate(fd, 1 << 40) in the box: {over['ftruncate']} (expected EFBIG)"
    )
    assert _host_size(big_fd) <= limit, f"the host sees {_host_size(big_fd)} bytes"
    under = _probe(box, tree, "ftruncate", small_fd, limit // 2)
    assert under["ftruncate"] == "ok", f"control: in-limit ftruncate refused: {under}"
    assert _host_size(small_fd) == limit // 2, "control: the in-limit ftruncate did not land"


def _assert_rlimit_is(box, tree: Path, limit: int) -> None:
    """O2: the limit every exec'd process holds, read where it applies — `getrlimit` inside the
    box, in bytes, soft and hard both equal to the limit."""
    seen = _probe(box, tree, "getrlimit", tree / "unused", 0)
    assert seen["fsize"] == [limit, limit], (
        f"RLIMIT_FSIZE inside the box is {seen['fsize']}, expected [{limit}, {limit}]"
    )


def _expected(size: int) -> bytes:
    block = bytes(range(256)) * 256
    return (block * (size // len(block) + 1))[:size]


def _assert_real_write_stops_at_the_limit(box, tree: Path, limit: int) -> None:
    """O1/O2: a REAL write past the limit — data, not a hole — onto the writable tree (never
    `/tmp`, whose tmpfs cap would answer ENOSPC first) stops: EFBIG in the box, and the host
    sees at most `limit` bytes. Control on the same tree: a write under the limit lands with
    exactly the bytes written."""
    past = tree / "write-past"
    over = _probe(box, tree, "write", past, 2 * limit)
    assert over["errno"] == errno.EFBIG, f"a write past the limit was not refused: {over}"
    assert over["written"] <= limit, f"the box wrote {over['written']} bytes (limit {limit})"
    assert _host_size(past) <= limit, f"the host sees {_host_size(past)} bytes (limit {limit})"

    within = tree / "write-within"
    under = _probe(box, tree, "write", within, limit // 2)
    assert under == {"written": limit // 2, "errno": None}, f"control: {under}"
    assert within.read_bytes() == _expected(limit // 2), (
        "control: the in-limit write did not land on the host byte for byte"
    )


def _assert_the_box_cannot_lift_it(box, tree: Path, limit: int) -> None:
    """O3 (M2): a process in the box cannot raise the limit — not to unlimited, not by one byte
    of hard limit, not through the shell's `ulimit -H -f unlimited` — and the limit it holds
    afterwards is unchanged. Control in the same process: lowering it succeeds."""
    seen = _probe(box, tree, "lift", tree / "unused", limit)
    assert seen["before"] == [limit, limit], f"the box did not start at the limit: {seen}"
    assert seen["unlimited"] != "ok", "setrlimit(RLIMIT_FSIZE, unlimited) succeeded in the box"
    assert seen["hard_plus_one"] != "ok", "the box raised its hard file-size limit past L"
    assert seen["sh_hard_unlimited"] != 0, "`ulimit -H -f unlimited` succeeded in the box"
    assert seen["after"] == [limit, limit], f"the limit moved after the attempts: {seen}"
    assert seen["sh_lower_soft"] == 0, f"control: the shell could not even lower it: {seen}"
    assert seen["lower_soft"] == "ok", f"control: setrlimit is unreachable, not refused: {seen}"
    assert seen["lowered"] == [limit // 2, limit], f"control: lowering did not take: {seen}"


@requires_box_daemon
@RUNTIMES
def test_a_live_investigation_box_cannot_write_past_the_read_cap(runtime, base):
    """O1/O2 under the DEFAULT spec, investigation lane, under each runtime: the box an
    investigation actually gets holds RLIMIT_FSIZE = READ_LIMIT, soft and hard, in every
    exec'd process, and a sparse file extended past it (`truncate -s 1T`, `ftruncate`) is
    refused with the host seeing nothing over the cap.

    Red at HEAD for the substantive reason, needing no new field: no limit is in force, so the
    box reads RLIMIT_FSIZE as unlimited and the 1 TiB extension succeeds."""
    _need_runtime(runtime)
    run_dir = _run_dir(base)
    with _investigation_box(run_dir, _spec(runtime)) as box:
        _assert_rlimit_is(box, run_dir, READ_LIMIT)
        _assert_sparse_extension_is_bounded(box, run_dir, READ_LIMIT)
        _assert_the_box_cannot_lift_it(box, run_dir, READ_LIMIT)


@requires_box_daemon
@RUNTIMES
def test_a_live_lane_box_cannot_write_past_the_read_cap(runtime, base):
    """O1/O2 under the DEFAULT spec, lane path (`BoxRequest`), under each runtime: the same
    limit and the same refusals on the lane box's writable mount."""
    _need_runtime(runtime)
    with _lane_box(base, _spec(runtime)) as (box, tree):
        _assert_rlimit_is(box, tree, READ_LIMIT)
        _assert_sparse_extension_is_bounded(box, tree, READ_LIMIT)
        _assert_the_box_cannot_lift_it(box, tree, READ_LIMIT)


@requires_box_daemon
@RUNTIMES
def test_a_live_investigation_box_enforces_its_spec_limit_and_cannot_lift_it(runtime, base):
    """O1/O2/O3 at a small spec limit, investigation lane, under each runtime: the limit the
    spec names is the one in force; a real write past it stops on the run-dir bind with the
    host seeing at most L bytes while a write under it lands exactly; a sparse extension past
    it is refused; and nothing in the box can raise it."""
    _need_runtime(runtime)
    run_dir = _run_dir(base)
    with _investigation_box(run_dir, _spec(runtime, SMALL_LIMIT)) as box:
        _assert_rlimit_is(box, run_dir, SMALL_LIMIT)
        _assert_real_write_stops_at_the_limit(box, run_dir, SMALL_LIMIT)
        _assert_sparse_extension_is_bounded(box, run_dir, SMALL_LIMIT)
        _assert_the_box_cannot_lift_it(box, run_dir, SMALL_LIMIT)


@requires_box_daemon
@RUNTIMES
def test_a_live_lane_box_enforces_its_spec_limit_and_cannot_lift_it(runtime, base):
    """O1/O2/O3 at a small spec limit, lane path, under each runtime: the request spec's limit
    is in force on the writable mount — a real write past it stops, one under it lands
    exactly — and the box cannot raise it."""
    _need_runtime(runtime)
    with _lane_box(base, _spec(runtime, SMALL_LIMIT)) as (box, tree):
        _assert_rlimit_is(box, tree, SMALL_LIMIT)
        _assert_real_write_stops_at_the_limit(box, tree, SMALL_LIMIT)
        _assert_the_box_cannot_lift_it(box, tree, SMALL_LIMIT)
